import cv2
import base64
import io

def capture_webcam():
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    if ret:
        _, buffer = cv2.imencode('.jpg', frame)
        img_str = base64.b64encode(buffer.tobytes()).decode()
        return img_str
    return None