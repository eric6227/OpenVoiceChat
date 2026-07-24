"""Reliable UDP protocol for control messages.

Provides a simple request-response-acknowledge mechanism over UDP
for control messages that need reliability (auth, user list, events, etc.).

Protocol format:
    [msg_type(1)][seq_num(2)][flags(1)][payload_len(4)][payload(N)]

Flags:
    0x01 - NEEDS_ACK: sender expects an ACK for this message
    0x02 - IS_ACK: this message is an acknowledgment
    0x04 - IS_RESPONSE: this message is a response to a request

Audio packets use a different format and are NOT handled by this module.
"""

import socket
import struct
import time
import threading
import logging

logger = logging.getLogger(__name__)

# RUDP constants
RUDP_FLAG_NEEDS_ACK = 0x01
RUDP_FLAG_IS_ACK = 0x02
RUDP_FLAG_IS_RESPONSE = 0x04

RUDP_HEADER_SIZE = 8  # msg_type(1) + seq_num(2) + flags(1) + payload_len(4)
RUDP_RETRANSMIT_TIMEOUT = 0.5  # 500ms
RUDP_MAX_RETRANSMITS = 5
RUDP_ACK_TIMEOUT = 0.3  # Time to wait for ACK before retransmitting


def pack_rudp_message(msg_type, seq_num, flags, payload=b''):
    """Pack a RUDP message into bytes."""
    header = struct.pack('!BHB', msg_type, seq_num, flags)
    header += struct.pack('!I', len(payload))
    return header + payload


def unpack_rudp_message(data):
    """Unpack a RUDP message from bytes.
    
    Returns (msg_type, seq_num, flags, payload) or None if invalid.
    """
    if len(data) < RUDP_HEADER_SIZE:
        return None
    msg_type = struct.unpack('!B', data[:1])[0]
    seq_num = struct.unpack('!H', data[1:3])[0]
    flags = struct.unpack('!B', data[3:4])[0]
    payload_len = struct.unpack('!I', data[4:8])[0]
    if len(data) < RUDP_HEADER_SIZE + payload_len:
        return None
    payload = data[8:8+payload_len]
    return (msg_type, seq_num, flags, payload)


def pack_ack(msg_type, seq_num):
    """Pack an ACK message."""
    return pack_rudp_message(msg_type, seq_num, RUDP_FLAG_IS_ACK)


def pack_response(msg_type, seq_num, payload=b''):
    """Pack a response message (needs ACK from receiver)."""
    return pack_rudp_message(msg_type, seq_num, RUDP_FLAG_NEEDS_ACK | RUDP_FLAG_IS_RESPONSE, payload)


def pack_request(msg_type, seq_num, payload=b''):
    """Pack a request message (needs response from receiver)."""
    return pack_rudp_message(msg_type, seq_num, RUDP_FLAG_NEEDS_ACK, payload)


class RUDPEndpoint:
    """Manages reliable UDP communication for one endpoint.
    
    Handles:
    - Sequence number tracking
    - Retransmission of unacknowledged messages
    - ACK sending
    - Duplicate detection (for received messages)
    - Request-response matching
    """
    
    def __init__(self, sock, addr, max_pending=100):
        """
        Args:
            sock: The UDP socket to send/receive on
            addr: The remote address (host, port)
            max_pending: Maximum number of pending (unacked) messages
        """
        self.sock = sock
        self.addr = addr
        self._seq_num = 0
        self._lock = threading.Lock()
        self._pending = {}  # seq_num -> (packet, retry_count, last_send_time, event)
        self._pending_lock = threading.Lock()
        self._response_data = {}  # seq_num -> (msg_type, payload) for received responses
        self._response_lock = threading.Lock()
        self._received_seqs = set()  # For duplicate detection
        self._max_received = 1000
        self._running = threading.Event()
        self._running.set()
        self._retransmit_thread = threading.Thread(target=self._retransmit_loop, daemon=True)
        self._retransmit_thread.start()
    
    def stop(self):
        """Stop the endpoint."""
        self._running.clear()
        with self._pending_lock:
            for seq_num, (packet, retry_count, last_send, event) in list(self._pending.items()):
                event.set()
            self._pending.clear()
        with self._response_lock:
            self._response_data.clear()
    
    def next_seq(self):
        """Get the next sequence number."""
        with self._lock:
            seq = self._seq_num
            self._seq_num = (self._seq_num + 1) & 0xFFFF
            return seq
    
    def send_and_wait(self, msg_type, payload=b'', timeout=5.0):
        """Send a request and wait for the response.
        
        Args:
            msg_type: Message type
            payload: Message payload
            timeout: Maximum time to wait for response
            
        Returns:
            (msg_type, payload) of the response, or None on timeout.
        """
        seq_num = self.next_seq()
        packet = pack_rudp_message(msg_type, seq_num, RUDP_FLAG_NEEDS_ACK, payload)
        
        event = threading.Event()
        with self._pending_lock:
            self._pending[seq_num] = (packet, 0, time.time(), event)
        
        try:
            self.sock.sendto(packet, self.addr)
        except Exception as e:
            logger.error(f"RUDP send error: {e}")
            with self._pending_lock:
                self._pending.pop(seq_num, None)
            return None
        
        # Start a background receiver to process incoming responses
        stop_recv = threading.Event()
        
        def _recv_loop():
            prev_timeout = self.sock.gettimeout()
            self.sock.settimeout(0.1)
            try:
                while not stop_recv.is_set():
                    try:
                        data, addr = self.sock.recvfrom(65535)
                        self.handle_incoming(data)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
            finally:
                try:
                    self.sock.settimeout(prev_timeout)
                except OSError:
                    pass  # Socket may have been closed during cleanup
        
        recv_thread = threading.Thread(target=_recv_loop, daemon=True)
        recv_thread.start()
        
        # Wait for the response (poll for response data, not just event)
        deadline = time.time() + timeout
        resp = None
        while time.time() < deadline:
            if event.wait(0.05):
                # Event was signaled, check for response data
                with self._response_lock:
                    if seq_num in self._response_data:
                        resp = self._response_data.pop(seq_num)
                        break
            # Also check without event (defense against race)
            with self._response_lock:
                if seq_num in self._response_data:
                    resp = self._response_data.pop(seq_num)
                    break
        
        # Stop the background receiver
        stop_recv.set()
        recv_thread.join(timeout=1.0)
        
        with self._pending_lock:
            self._pending.pop(seq_num, None)
        with self._response_lock:
            self._response_data.pop(seq_num, None)
        
        if resp is None:
            logger.warning(f"RUDP: No response for seq={seq_num}")
        
        return resp
    
    def send(self, msg_type, payload=b'', timeout=5.0):
        """Send a message reliably (with ACK).
        
        Args:
            msg_type: Message type
            payload: Message payload
            timeout: Maximum time to wait for ACK
            
        Returns:
            True if ACK received, False otherwise.
        """
        seq_num = self.next_seq()
        packet = pack_rudp_message(msg_type, seq_num, RUDP_FLAG_NEEDS_ACK, payload)
        
        event = threading.Event()
        with self._pending_lock:
            self._pending[seq_num] = (packet, 0, time.time(), event)
        
        try:
            self.sock.sendto(packet, self.addr)
        except Exception as e:
            logger.error(f"RUDP send error: {e}")
            with self._pending_lock:
                self._pending.pop(seq_num, None)
            return False
        
        # Wait for ACK
        if not event.wait(timeout):
            logger.warning(f"RUDP: No ACK for seq={seq_num}")
            with self._pending_lock:
                self._pending.pop(seq_num, None)
            return False
        
        with self._pending_lock:
            self._pending.pop(seq_num, None)
        return True
    
    def send_raw(self, msg_type, payload=b''):
        """Send a message without reliability (fire and forget)."""
        seq_num = self.next_seq()
        packet = pack_rudp_message(msg_type, seq_num, 0, payload)
        try:
            self.sock.sendto(packet, self.addr)
        except Exception as e:
            logger.error(f"RUDP raw send error: {e}")
    
    def handle_incoming_wait(self, timeout=5.0):
        """Wait for an incoming message from the server.
        
        This is a blocking call that waits for a non-ACK, non-response message.
        
        Args:
            timeout: Maximum time to wait
            
        Returns:
            (msg_type, payload) or None on timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = self.sock.recvfrom(65535)
                result = self.handle_incoming(data)
                if result is not None:
                    return result
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.01)
                continue
            except Exception as e:
                logger.error(f"RUDP recv error: {e}")
                time.sleep(0.1)
                continue
        return None
    
    def close(self):
        """Stop the endpoint and clean up."""
        self.stop()
    
    def handle_incoming(self, data):
        """Handle an incoming RUDP message.
        
        Args:
            data: Raw packet data
            
        Returns:
            (msg_type, payload) for unsolicited messages from server,
            None for ACKs and responses to pending requests.
        """
        result = unpack_rudp_message(data)
        if result is None:
            return None
        
        msg_type, seq_num, flags, payload = result
        
        # If this is an ACK, do NOT signal the event.
        # The event should only be signaled by the response (IS_RESPONSE)
        # or by max retries in the retransmit loop.
        # Signaling on ACK causes a race condition in send_and_wait()
        # where the ACK arrives before the response data is stored.
        if flags & RUDP_FLAG_IS_ACK:
            return None
        
        # If this is a response to our request, store it and signal
        if flags & RUDP_FLAG_IS_RESPONSE:
            with self._response_lock:
                self._response_data[seq_num] = (msg_type, payload)
            with self._pending_lock:
                if seq_num in self._pending:
                    self._pending[seq_num][3].set()
            # Send ACK for the response
            if flags & RUDP_FLAG_NEEDS_ACK:
                ack = pack_ack(msg_type, seq_num)
                try:
                    self.sock.sendto(ack, self.addr)
                except Exception:
                    pass
            return None
        
        # This is an unsolicited message from the server
        # Send ACK if requested
        if flags & RUDP_FLAG_NEEDS_ACK:
            ack = pack_ack(msg_type, seq_num)
            try:
                self.sock.sendto(ack, self.addr)
            except Exception:
                pass
        
        # Check duplicate
        if self.is_duplicate(seq_num):
            return None
        
        return (msg_type, payload)
    
    def handle_ack(self, seq_num):
        """Handle an incoming ACK for a sequence number."""
        with self._pending_lock:
            if seq_num in self._pending:
                self._pending[seq_num][3].set()  # signal the event
    
    def is_duplicate(self, seq_num):
        """Check if a sequence number has been seen before.
        
        Returns True if duplicate, False if new.
        """
        if seq_num in self._received_seqs:
            return True
        self._received_seqs.add(seq_num)
        if len(self._received_seqs) > self._max_received:
            # Keep only the most recent half
            self._received_seqs = set(list(self._received_seqs)[-self._max_received//2:])
        return False
    
    def _retransmit_loop(self):
        """Background thread for retransmitting unacknowledged messages."""
        while self._running.is_set():
            self._retransmit_pending()
            time.sleep(0.1)
    
    def _retransmit_pending(self):
        """Check and retransmit pending messages."""
        now = time.time()
        with self._pending_lock:
            to_retransmit = []
            to_remove = []
            for seq_num, (packet, retry_count, last_send, event) in list(self._pending.items()):
                if event.is_set():
                    # Already got ACK, clean up
                    to_remove.append(seq_num)
                    continue
                if now - last_send > RUDP_RETRANSMIT_TIMEOUT:
                    if retry_count >= RUDP_MAX_RETRANSMITS:
                        logger.warning(f"RUDP: Max retransmits reached for seq={seq_num}")
                        event.set()  # Signal failure
                        to_remove.append(seq_num)
                    else:
                        to_retransmit.append((seq_num, packet, retry_count))
            
            for seq_num in to_remove:
                self._pending.pop(seq_num, None)
            
            for seq_num, packet, retry_count in to_retransmit:
                try:
                    self.sock.sendto(packet, self.addr)
                    self._pending[seq_num] = (packet, retry_count + 1, now, self._pending[seq_num][3])
                except Exception as e:
                    logger.error(f"RUDP retransmit error for seq={seq_num}: {e}")


class RUDPServer:
    """Server-side RUDP manager.
    
    Manages RUDP communication with multiple clients.
    Each client is identified by its address (host, port).
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._response_queues = {}  # addr -> {seq_num: response_data}
        self._seq_counters = {}  # addr -> current_seq_num
    
    def get_seq(self, addr):
        """Get next sequence number for an address."""
        with self._lock:
            if addr not in self._seq_counters:
                self._seq_counters[addr] = 0
            seq = self._seq_counters[addr]
            self._seq_counters[addr] = (seq + 1) & 0xFFFF
            return seq
    
    def handle_message(self, sock, data, addr):
        """Handle an incoming RUDP message.
        
        Args:
            sock: UDP socket to send responses on
            data: Raw packet data
            addr: Sender's address (host, port)
            
        Returns:
            (msg_type, seq_num, flags, payload) or None if it's an ACK/duplicate
        """
        result = unpack_rudp_message(data)
        if result is None:
            return None
        
        msg_type, seq_num, flags, payload = result
        
        # If this is an ACK, remove the stored response (client acknowledged it)
        if flags & RUDP_FLAG_IS_ACK:
            with self._lock:
                if addr in self._response_queues:
                    self._response_queues[addr].pop(seq_num, None)
            return None  # ACK processed, nothing to return
        
        # If this is a retransmission, re-send the stored response
        if self._has_response(addr, seq_num):
            response = self._get_stored_response(addr, seq_num)
            if response:
                resp_type, resp_payload = response
                resp_packet = pack_response(resp_type, seq_num, resp_payload)
                try:
                    sock.sendto(resp_packet, addr)
                except Exception:
                    pass
            return None  # Duplicate, already handled
        
        # Send ACK if requested
        if flags & RUDP_FLAG_NEEDS_ACK:
            ack = pack_ack(msg_type, seq_num)
            try:
                sock.sendto(ack, addr)
            except Exception:
                pass
        
        return (msg_type, seq_num, flags, payload)
    
    def send_response(self, sock, addr, msg_type, seq_num, payload=b''):
        """Send a response to a request and store it for retransmission."""
        self._store_response(addr, seq_num, msg_type, payload)
        packet = pack_response(msg_type, seq_num, payload)
        try:
            sock.sendto(packet, addr)
        except Exception as e:
            logger.error(f"RUDP send_response error: {e}")
    
    def send_message(self, sock, addr, msg_type, payload=b'', seq_num=None):
        """Send a message to a client (server-initiated).
        
        The message will be retransmitted until ACKed.
        """
        if seq_num is None:
            seq_num = self.get_seq(addr)
        self._store_response(addr, seq_num, msg_type, payload)
        packet = pack_request(msg_type, seq_num, payload)
        try:
            sock.sendto(packet, addr)
        except Exception as e:
            logger.error(f"RUDP send_message error: {e}")
    
    def _store_response(self, addr, seq_num, msg_type, payload):
        """Store a response for potential retransmission."""
        with self._lock:
            if addr not in self._response_queues:
                self._response_queues[addr] = {}
            self._response_queues[addr][seq_num] = (msg_type, payload)
    
    def _has_response(self, addr, seq_num):
        """Check if we have a stored response for this address and seq_num."""
        with self._lock:
            return addr in self._response_queues and seq_num in self._response_queues[addr]
    
    def _get_stored_response(self, addr, seq_num):
        """Get a stored response."""
        with self._lock:
            return self._response_queues.get(addr, {}).get(seq_num)
    
    def cleanup_addr(self, addr):
        """Clean up state for a disconnected address."""
        with self._lock:
            self._response_queues.pop(addr, None)
            self._seq_counters.pop(addr, None)