#!/usr/bin/env python3
"""
E.D.I.T.H - Zero-Day Intrusion Detection & Automated Response System
AI-driven behavioral anomaly detection for identifying zero-day attacks
Version: 1.0 | Backend-Only Prototype
"""

import random
import statistics
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Dict, Tuple


class EventType(Enum):
    """Types of system events to monitor"""
    CPU_USAGE = "CPU_USAGE"
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    FILE_ACCESS = "FILE_ACCESS"
    PROCESS_CREATION = "PROCESS_CREATION"


class Severity(Enum):
    """Threat severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class SystemEvent:
    """Represents a system event for behavioral monitoring"""
    timestamp: datetime
    event_type: EventType
    value: float
    source: str
    metadata: Dict[str, any]
    
    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.event_type.value}: {self.source} = {self.value:.2f}"


@dataclass
class Alert:
    """Security alert container"""
    severity: Severity
    reason: str
    response: str
    event: SystemEvent
    timestamp: datetime
    
    def __str__(self):
        return f"""
        ⚠️  ALERT ⚠️
        Time: {self.timestamp.strftime('%H:%M:%S')}
        Severity: {self.severity.value}
        Reason: {self.reason}
        Event: {self.event}
        Response: {self.response}
        {'='*50}
        """


class BehavioralAIEngine:
    """AI Engine for behavioral anomaly detection"""
    
    def __init__(self, baseline_window: int = 50):
        self.baseline_window = baseline_window
        self.baseline_data = {et: deque(maxlen=baseline_window) for et in EventType}
        self.baseline_established = {et: False for et in EventType}
        self.deviation_thresholds = {
            EventType.CPU_USAGE: 3.0,      # 3 standard deviations
            EventType.NETWORK_TRAFFIC: 3.5,
            EventType.LOGIN_ATTEMPT: 4.0,
            EventType.FILE_ACCESS: 3.0,
            EventType.PROCESS_CREATION: 3.5
        }
        self.anomaly_history = []
        
    def learn_baseline(self, event: SystemEvent) -> None:
        """Learn normal behavior baseline"""
        self.baseline_data[event.event_type].append(event.value)
        
        # Mark baseline as established when we have enough data
        if len(self.baseline_data[event.event_type]) >= self.baseline_window:
            self.baseline_established[event.event_type] = True
    
    def detect_anomaly(self, event: SystemEvent) -> Tuple[bool, Severity, str]:
        """Detect behavioral anomalies using statistical deviation"""
        
        # Skip detection if baseline not established
        if not self.baseline_established[event.event_type]:
            return False, Severity.LOW, "Baseline learning"
        
        data = list(self.baseline_data[event.event_type])
        current = event.value
        
        # Calculate statistical metrics
        try:
            mean = statistics.mean(data)
            stdev = statistics.stdev(data) if len(data) > 1 else 0.1
            z_score = abs((current - mean) / stdev) if stdev > 0 else 0
        except statistics.StatisticsError:
            return False, Severity.LOW, "Insufficient baseline data"
        
        threshold = self.deviation_thresholds[event.event_type]
        
        # Check for spike anomaly (zero-day indicator)
        if z_score > threshold:
            # Determine severity based on deviation magnitude
            if z_score > threshold * 2:
                severity = Severity.HIGH
                reason = f"Extreme behavioral deviation (z-score: {z_score:.2f})"
            elif z_score > threshold * 1.5:
                severity = Severity.MEDIUM
                reason = f"Significant behavioral deviation (z-score: {z_score:.2f})"
            else:
                severity = Severity.LOW
                reason = f"Moderate behavioral deviation (z-score: {z_score:.2f})"
            
            # Check for rapid successive anomalies (attack pattern)
            recent_anomalies = sum(1 for ts, _ in self.anomaly_history[-5:] 
                                 if (datetime.now() - ts).seconds < 10)
            if recent_anomalies >= 3:
                severity = Severity.HIGH
                reason = f"Rapid anomaly pattern detected ({recent_anomalies} in 10s)"
            
            self.anomaly_history.append((datetime.now(), event.event_type))
            return True, severity, reason
        
        # Check for ratio-based anomalies (sudden drops can also be suspicious)
        if event.event_type == EventType.NETWORK_TRAFFIC:
            if mean > 0 and current / mean < 0.1:  # 90% drop in traffic
                return True, Severity.MEDIUM, "Network traffic collapse (possible DoS)"
        
        return False, Severity.LOW, "Normal behavior"
    
    def get_baseline_status(self) -> Dict:
        """Return baseline establishment status"""
        return {et.value: established for et, established in self.baseline_established.items()}


class DataSimulator:
    """Simulates system events including zero-day attacks"""
    
    def __init__(self):
        self.normal_ranges = {
            EventType.CPU_USAGE: (5.0, 40.0),           # 5-40% CPU usage
            EventType.NETWORK_TRAFFIC: (10.0, 200.0),   # 10-200 MB
            EventType.LOGIN_ATTEMPT: (0.0, 2.0),        # 0-2 attempts per minute
            EventType.FILE_ACCESS: (5.0, 50.0),         # 5-50 files per minute
            EventType.PROCESS_CREATION: (0.0, 5.0)      # 0-5 new processes per minute
        }
        self.sources = ["server-01", "server-02", "workstation-01", "workstation-02"]
        self.event_counter = 0
        self.attack_in_progress = False
        
    def generate_normal_event(self) -> SystemEvent:
        """Generate a normal system event"""
        self.event_counter += 1
        
        # Randomly select event type with weighted distribution
        weights = [0.25, 0.25, 0.15, 0.20, 0.15]
        event_type = random.choices(list(EventType), weights=weights)[0]
        
        # Generate normal value within range
        min_val, max_val = self.normal_ranges[event_type]
        value = random.uniform(min_val, max_val)
        
        # Add slight variations to simulate real patterns
        if event_type == EventType.CPU_USAGE and self.event_counter % 20 == 0:
            value = min_val * 1.5  # Small CPU spike
        
        source = random.choice(self.sources)
        
        metadata = {
            "pid": random.randint(1000, 9999) if event_type == EventType.PROCESS_CREATION else None,
            "user": f"user{random.randint(1, 20)}" if event_type == EventType.LOGIN_ATTEMPT else "system",
            "protocol": random.choice(["TCP", "UDP"]) if event_type == EventType.NETWORK_TRAFFIC else None
        }
        
        return SystemEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            value=value,
            source=source,
            metadata=metadata
        )
    
    def generate_zero_day_attack(self) -> SystemEvent:
        """Simulate a zero-day attack event (sudden extreme behavior)"""
        attack_type = random.choice([
            "cpu_exploit", "network_flood", "brute_force", 
            "file_exfiltration", "process_injection"
        ])
        
        if attack_type == "cpu_exploit":
            event_type = EventType.CPU_USAGE
            value = random.uniform(95.0, 100.0)  # CPU spike to 95-100%
            reason = "Cryptominer/CPU exploitation"
            
        elif attack_type == "network_flood":
            event_type = EventType.NETWORK_TRAFFIC
            value = random.uniform(800.0, 1500.0)  # Massive traffic spike
            reason = "DDoS/Network flood attack"
            
        elif attack_type == "brute_force":
            event_type = EventType.LOGIN_ATTEMPT
            value = random.uniform(20.0, 50.0)  # Rapid login attempts
            reason = "Brute force authentication attack"
            
        elif attack_type == "file_exfiltration":
            event_type = EventType.FILE_ACCESS
            value = random.uniform(200.0, 500.0)  # Massive file access
            reason = "Data exfiltration attack"
            
        else:  # process_injection
            event_type = EventType.PROCESS_CREATION
            value = random.uniform(20.0, 40.0)  # Rapid process creation
            reason = "Process injection/privilege escalation"
        
        source = random.choice(["malicious-external", "compromised-internal"])
        
        metadata = {
            "attack_type": attack_type,
            "reason": reason,
            "zero_day": True,
            "signature": "UNKNOWN"  # Zero-day = no known signature
        }
        
        return SystemEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            value=value,
            source=source,
            metadata=metadata
        )
    
    def generate_event_sequence(self, total_events: int = 100) -> List[SystemEvent]:
        """Generate mixed sequence of normal and attack events"""
        events = []
        
        for i in range(total_events):
            # Inject zero-day attack at specific intervals
            if i in [25, 50, 75] or (random.random() < 0.05 and i > 30):
                self.attack_in_progress = True
                attack_event = self.generate_zero_day_attack()
                events.append(attack_event)
                
                # Add follow-up events for multi-stage attacks
                if random.random() < 0.7:
                    for _ in range(random.randint(1, 3)):
                        follow_up = self.generate_zero_day_attack()
                        follow_up.value *= 0.5  # Slightly less severe follow-up
                        events.append(follow_up)
                        time.sleep(0.1)
                
                self.attack_in_progress = False
            
            # Generate normal event
            events.append(self.generate_normal_event())
            time.sleep(0.05)  # Simulate real-time event stream
        
        return events


class AutomatedResponder:
    """Executes automated responses based on threat severity"""
    
    def __init__(self):
        self.response_log = []
        self.blocked_sources = set()
        self.isolation_mode = False
        
    def execute_response(self, severity: Severity, event: SystemEvent) -> str:
        """Execute automated response based on severity"""
        
        if severity == Severity.HIGH:
            response = self._handle_high_severity(event)
        elif severity == Severity.MEDIUM:
            response = self._handle_medium_severity(event)
        else:
            response = self._handle_low_severity(event)
        
        self.response_log.append({
            "timestamp": datetime.now(),
            "severity": severity,
            "source": event.source,
            "response": response
        })
        
        return response
    
    def _handle_high_severity(self, event: SystemEvent) -> str:
        """High severity response: isolation and blocking"""
        self.blocked_sources.add(event.source)
        self.isolation_mode = True
        
        responses = [
            f"Isolated source {event.source} from network",
            f"Blocked all traffic from {event.source}",
            f"Initiated forensic capture for {event.source}",
            f"Deployed honeypot to monitor attack patterns",
            f"Alerted SOC team for immediate investigation"
        ]
        
        return " | ".join(responses[:2])  # Return first 2 responses
    
    def _handle_medium_severity(self, event: SystemEvent) -> str:
        """Medium severity response: enhanced monitoring"""
        responses = [
            f"Increased monitoring on {event.source}",
            f"Applied rate limiting to {event.source}",
            f"Initiated behavioral analysis on {event.source}",
            f"Logged detailed forensic data for {event.source}"
        ]
        
        return " | ".join(responses[:2])
    
    def _handle_low_severity(self, event: SystemEvent) -> str:
        """Low severity response: logging only"""
        return f"Logged anomaly for {event.source} - monitoring continued"
    
    def get_response_summary(self) -> Dict:
        """Get response execution summary"""
        return {
            "total_responses": len(self.response_log),
            "blocked_sources": list(self.blocked_sources),
            "high_severity_actions": sum(1 for r in self.response_log if r["severity"] == Severity.HIGH)
        }


class EDITHController:
    """Main controller orchestrating the E.D.I.T.H system"""
    
    def __init__(self):
        self.ai_engine = BehavioralAIEngine(baseline_window=30)
        self.data_simulator = DataSimulator()
        self.responder = AutomatedResponder()
        self.alerts = []
        self.event_log = []
        self.total_events_processed = 0
        self.detection_start_time = None
        
    def run_detection_cycle(self, total_events: int = 80) -> None:
        """Execute full detection and response cycle"""
        print("🚀 E.D.I.T.H Zero-Day Intrusion Detection System")
        print("🔍 Learning normal behavior baseline...")
        print("-" * 60)
        
        self.detection_start_time = datetime.now()
        
        # Generate and process events
        events = self.data_simulator.generate_event_sequence(total_events)
        
        for event in events:
            self.total_events_processed += 1
            self.event_log.append(event)
            
            # Display event in real-time
            event_color = "\033[91m" if event.metadata.get("zero_day") else "\033[92m"
            print(f"{event_color}{event}\033[0m")
            
            # Learn baseline from initial normal events
            if self.total_events_processed <= 30 and not event.metadata.get("zero_day"):
                self.ai_engine.learn_baseline(event)
                print(f"   📚 Learning baseline for {event.event_type.value}...")
                continue
            
            # Detect anomalies
            is_anomaly, severity, reason = self.ai_engine.detect_anomaly(event)
            
            if is_anomaly:
                # Generate automated response
                response = self.responder.execute_response(severity, event)
                
                # Create and store alert
                alert = Alert(
                    severity=severity,
                    reason=reason,
                    response=response,
                    event=event,
                    timestamp=datetime.now()
                )
                self.alerts.append(alert)
                
                # Display alert
                print(str(alert))
                
                # Pause briefly for alert visibility
                time.sleep(0.5)
            
            # Update baseline with non-attack events
            if not event.metadata.get("zero_day"):
                self.ai_engine.learn_baseline(event)
        
        self._print_final_summary()
    
    def _print_final_summary(self) -> None:
        """Print comprehensive security summary"""
        print("\n" + "="*60)
        print("📊 E.D.I.T.H SECURITY SUMMARY")
        print("="*60)
        
        # Timeline
        detection_time = (datetime.now() - self.detection_start_time).total_seconds()
        print(f"Detection Timeline: {detection_time:.1f} seconds")
        print(f"Events Processed: {self.total_events_processed}")
        
        # Baseline Status
        print("\n🔬 Behavioral Baseline Status:")
        baseline_status = self.ai_engine.get_baseline_status()
        for event_type, established in baseline_status.items():
            status = "✅ ESTABLISHED" if established else "⏳ LEARNING"
            print(f"  {event_type}: {status}")
        
        # Alert Summary
        print("\n🚨 Threat Detection Summary:")
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert.severity] += 1
        
        for severity in Severity:
            count = severity_counts[severity]
            percentage = (count / len(self.alerts) * 100) if self.alerts else 0
            print(f"  {severity.value}: {count} alerts ({percentage:.1f}%)")
        
        print(f"\n  Total Alerts: {len(self.alerts)}")
        
        # Response Summary
        response_summary = self.responder.get_response_summary()
        print("\n🛡️  Automated Response Summary:")
        print(f"  Responses Executed: {response_summary['total_responses']}")
        print(f"  High-Severity Actions: {response_summary['high_severity_actions']}")
        
        if response_summary['blocked_sources']:
            print(f"  Blocked Sources: {', '.join(response_summary['blocked_sources'])}")
        else:
            print("  Blocked Sources: None")
        
        # Detection Efficacy
        print("\n📈 Detection Efficacy:")
        simulated_attacks = sum(1 for e in self.event_log if e.metadata.get("zero_day"))
        detected_attacks = sum(1 for a in self.alerts if a.event.metadata.get("zero_day"))
        
        if simulated_attacks > 0:
            detection_rate = (detected_attacks / simulated_attacks) * 100
            print(f"  Zero-Day Attacks Simulated: {simulated_attacks}")
            print(f"  Zero-Day Attacks Detected: {detected_attacks}")
            print(f"  Detection Rate: {detection_rate:.1f}%")
        else:
            print("  No attacks simulated in this cycle")
        
        # System Status
        print("\n💡 System Status:")
        if len(self.alerts) == 0:
            print("  ✅ SYSTEM SECURE: No anomalies detected")
        elif severity_counts[Severity.HIGH] > 0:
            print("  🔴 CRITICAL THREATS: High severity alerts require review")
        elif severity_counts[Severity.MEDIUM] > 0:
            print("  🟡 ELEVATED RISK: Medium severity alerts detected")
        else:
            print("  🟢 LOW RISK: Only low severity anomalies detected")
        
        print("="*60)
        print("E.D.I.T.H Detection Cycle Complete")
        print("Behavioral AI remains active for continuous monitoring")


def main():
    """Main execution function"""
    # Set random seed for deterministic output
    random.seed(42)
    
    # Initialize and run E.D.I.T.H system
    edith = EDITHController()
    edith.run_detection_cycle(total_events=80)


if __name__ == "__main__":
    main()