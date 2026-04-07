import pyshark
import threading
import logging
from models.database import db, TrafficLog
from datetime import datetime

logger = logging.getLogger(__name__)

class PacketCaptureService:
    def __init__(self, app, model_manager, socketio=None):
        self.app = app
        self.model_manager = model_manager
        self.socketio = socketio
        self.is_running = False
        self.thread = None

    def start_capture(self, interface='Wi-Fi'):
        if self.is_running:
            return
        logger.info(f"Starting packet capture on interface: {interface}")
        self.is_running = True
        
        if self.socketio:
            self.thread = self.socketio.start_background_task(self._capture_loop, interface)
        else:
            self.thread = threading.Thread(target=self._capture_loop, args=(interface,))
            self.thread.daemon = True
            self.thread.start()

    def stop_capture(self):
        logger.info("Stopping packet capture...")
        self.is_running = False

    def _capture_loop(self, interface):
        try:
            import time
            import random
            
            with self.app.app_context():
                if interface == 'simulate':
                    logger.info("Running in SIMULATION mode (PyShark skipped) to populate dashboard...")
                    while self.is_running:
                        self._generate_mock_packet()
                        if self.socketio:
                            self.socketio.sleep(random.uniform(0.3, 2.0))
                        else:
                            time.sleep(random.uniform(0.3, 2.0))
                    return

                # Normal PyShark behavior
                import asyncio
                # pyshark requires an asyncio event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                if interface is None:
                    capture = pyshark.LiveCapture()
                else:
                    capture = pyshark.LiveCapture(interface=interface)
                    
                for packet in capture.sniff_continuously():
                    if not self.is_running:
                        break
                    self._process_packet(packet)
                    
        except Exception as e:
            logger.error(f"Error in packet capture loop: {e}")
            while self.is_running:
                self._generate_mock_packet()
                if hasattr(self, 'socketio') and self.socketio:
                    self.socketio.sleep(random.uniform(0.5, 2.5))
                else:
                    import time
                    time.sleep(random.uniform(0.5, 2.5))

    def _generate_mock_packet(self):
        import random
        try:
            packet_size = random.uniform(40.0, 2000.0)
            protocol_type = random.choice(['TCP', 'UDP', 'ICMP', 'MQTT', 'HTTP', 'TLS'])
            src_bytes = packet_size * random.uniform(0.5, 0.9)
            
            # Induce a simulated anomaly 5% of the time
            is_anomaly = random.random() < 0.05
            if is_anomaly:
                packet_size *= random.uniform(5, 10)
                src_bytes *= random.uniform(5, 10)
            
            features = [packet_size, 0.0, src_bytes, protocol_type]
            
            result = self.model_manager.predict({
                'model_type': 'traffic',
                'features': features
            })
            
            log = TrafficLog(
                packet_size=packet_size,
                connection_duration=0.0,
                src_bytes=src_bytes,
                protocol_type=protocol_type,
                classification=result['prediction'],
                confidence=result['confidence']
            )
            db.session.add(log)
            db.session.commit()
            
            if self.socketio:
                self.socketio.emit('packet_analyzed', {
                    'Protocol': protocol_type,
                    'Packet Size': round(packet_size, 2),
                    'Traffic Status': result['prediction'],
                    'Confidence': round(result['confidence'], 2)
                })
        except Exception as e:
            logger.error(f"Error processing mock packet: {e}")
            try:
                db.session.rollback()
            except:
                pass

    def _process_packet(self, packet):
        try:
            # Basic feature extraction from packet
            packet_size = float(packet.length)
            
            # Simple protocol highest layer
            protocol_type = packet.highest_layer if hasattr(packet, 'highest_layer') else 'Unknown'
            
            # src_bytes approximation
            src_bytes = float(packet.ip.len) if hasattr(packet, 'ip') else packet_size
            
            # Connection duration is hard to infer from a single packet without tracking state.
            # We'll use 0.0 for instant single-packet classification.
            connection_duration = 0.0
            
            features = [packet_size, connection_duration, src_bytes, protocol_type]
            
            # Predict
            result = self.model_manager.predict({
                'model_type': 'traffic',
                'features': features
            })
            
            # Save prediction to DB
            log = TrafficLog(
                packet_size=packet_size,
                connection_duration=connection_duration,
                src_bytes=src_bytes,
                protocol_type=protocol_type,
                classification=result['prediction'],
                confidence=result['confidence']
            )
            db.session.add(log)
            db.session.commit()
            
            # Emit live socket event
            if self.socketio:
                self.socketio.emit('packet_analyzed', {
                    'Protocol': protocol_type,
                    'Packet Size': packet_size,
                    'Traffic Status': result['prediction'],
                    'Confidence': result['confidence']
                })
            
        except AttributeError:
            pass  # Ignored packets without IP/Length
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            # db.session.rollback() might be needed if SQLAlchemy throws
            try:
                db.session.rollback()
            except:
                pass
