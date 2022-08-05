from queue import Queue
from abc import abstractmethod
from time import time, sleep
from threading import Thread
import os
import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2
from .error_utils import printGrpcError
class SwitchConnection(object):
    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0, low = 0):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.low = low
        self.channel_ready_flag = False
        self.requests_stream = IterableQueue()
        self.channel = grpc.insecure_channel(self.address, options=[("grpc.so_reuseport", 1),]) 
        self.channel.subscribe(self.wait_for_transient_failure)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        while (self.channel_ready_flag==False):
            pass
      
    def wait_for_transient_failure(self, channel_connectivity):
        try:
            if channel_connectivity != grpc.ChannelConnectivity.READY:
                self.channel_ready_flag = False
            else:
                self.channel_ready_flag = True
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)
    
    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        try:
            self.requests_stream.close()
            self.stream_msg_resp.cancel()
            self.channel.unsubscribe(self.wait_for_transient_failure)
            self.channel.close()
            print ("Device ID: [%d]: disconnected. "%self.device_id)
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)    
    
    def MasterArbitrationUpdate(self):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = self.low
        try:
            while (self.channel_ready_flag==False):
                pass
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)
            
    def SetConfigureForwardingPipeline(self, action, p4info, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = self.low
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()
        if action == 0:
            request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY
        elif action == 1:
            request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_SAVE
        elif action == 2:
            request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        elif action == 3:
            request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.COMMIT
        elif action == 4:
            request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.RECONCILE_AND_COMMIT
        try:
            while (self.channel_ready_flag==False):
                pass
            self.client_stub.SetForwardingPipelineConfig(request)
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)

    def WriteTableEntry(self, table_entries):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = self.low
        for action, message_type, entry in table_entries:
            update = request.updates.add()
            if action == 0:
                update.type = p4runtime_pb2.Update.INSERT
            elif action == 1:
                update.type = p4runtime_pb2.Update.MODIFY
            elif action == 2:
                update.type = p4runtime_pb2.Update.DELETE
            
            if (message_type == 0):
                update.entity.table_entry.CopyFrom(entry)
            elif (message_type == 1):
                update.entity.packet_replication_engine_entry.CopyFrom(entry)
        try:
            while (self.channel_ready_flag==False):
                pass
            self.client_stub.Write(request, timeout=60)
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)
    
    def PacketIn (self):
        try:
            while (self.channel_ready_flag==False):
                pass
            self.requests_stream.put(p4runtime_pb2.StreamMessageRequest())
            for item in self.stream_msg_resp:
                return item
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)
    
    def PacketOut (self, payload, metadata):
        request = p4runtime_pb2.StreamMessageRequest()
        packet = p4runtime_pb2.PacketOut()
        packet.payload = payload
        request.packet.CopyFrom(packet)
        for meta_id in range(len(metadata)):
            send_meta = request.packet.metadata.add()
            send_meta.metadata_id = meta_id+1
            send_meta.value = metadata[meta_id]
        try:
            while (self.channel_ready_flag==False):
                pass
            self.requests_stream.put(request)
        except grpc.RpcError as e:
            printGrpcError(e, self.device_id)
    
    def ReadTableEntries(self):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        table_entry.table_id = 0
        for response in self.client_stub.Read(request):
            yield response
    
class IterableQueue(Queue):
    _sentinel = object()
    def __iter__(self):
        return iter(self.get, self._sentinel)
    def close(self):
        self.put(self._sentinel)
