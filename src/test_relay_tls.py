import logging
from pathlib import Path
import time
from onion_relay import OnionRelay
import signal
import sys
from typing import Optional, List, Dict, Any, Union

class RelayTLSTest:
    def __init__(self):
        self.setup_logging()
        # Create test relays with different ports
        self.relays = [
            OnionRelay("test_relay_1", "127.0.0.1", 9001),
            OnionRelay("test_relay_2", "127.0.0.1", 9002),
            OnionRelay("test_relay_3", "127.0.0.1", 9003)
        ]
        self.setup_signal_handlers()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('RelayTLSTest')

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)

    def test_relay_upload_state(self, relay: OnionRelay) -> bool:
        """Test relay's ability to upload its state using TLS"""
        self.logger.info(f"\nTesting upload_state for relay {relay.name} ({relay.port})")
        try:
            success = relay.upload_state()
            self.logger.info(f"Upload state {'successful' if success else 'failed'}")
            return success
        except Exception as e:
            self.logger.error(f"Error during upload_state: {e}")
            return False

    def test_relay_download_states(self, relay: OnionRelay) -> bool:
        """Test relay's ability to download states using TLS"""
        self.logger.info(f"\nTesting download_states for relay {relay.name} ({relay.port})")
        try:
            states = relay.download_states()
            if states is not None:
                self.logger.info(f"Download states successful. Found {len(states)} relays")
                self.logger.info(f"States: {states}")
                return True
            self.logger.error("Download states failed")
            return False
        except Exception as e:
            self.logger.error(f"Error during download_states: {e}")
            return False

    def test_relay_heartbeat(self, relay: OnionRelay) -> bool:
        """Test relay's ability to send heartbeat using TLS"""
        self.logger.info(f"\nTesting heartbeat for relay {relay.name} ({relay.port})")
        try:
            success = relay.heartbeat()
            self.logger.info(f"Heartbeat {'successful' if success else 'failed'}")
            return success
        except Exception as e:
            self.logger.error(f"Error during heartbeat: {e}")
            return False

    def test_relay_continuous_operation(self, relay: OnionRelay, duration: int = 30) -> bool:
        """Test relay's continuous operation with TLS for a specified duration"""
        self.logger.info(f"\nTesting continuous operation for relay {relay.name} ({relay.port}) for {duration} seconds")
        try:
            # Start the relay
            relay.start()
            
            # Monitor for specified duration
            start_time = time.time()
            while time.time() - start_time < duration:
                # Check if states can be downloaded
                states = relay.download_states()
                if states is None:
                    self.logger.error("Failed to download states during continuous operation")
                    return False
                
                self.logger.info(f"Current number of active relays: {len(states)}")
                time.sleep(5)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error during continuous operation: {e}")
            return False
        finally:
            relay.shutdown()

    def verify_certificate_setup(self):
        """Verify that all necessary certificates exist and are accessible"""
        directory_cert = Path('../certs/tls/cert.pem')
        
        self.logger.info("\nVerifying certificate setup...")
        
        # Check directory server certificate
        if not directory_cert.exists():
            self.logger.error(f"Directory server certificate not found at {directory_cert}")
            return False
            
        # Check relay certificates
        for relay in self.relays:
            cert_file = Path(relay.certificates.tls_cert_file)
            key_file = Path(relay.certificates.tls_key_file)
            
            if not cert_file.exists():
                self.logger.error(f"Relay certificate not found at {cert_file}")
                return False
            if not key_file.exists():
                self.logger.error(f"Relay key not found at {key_file}")
                return False
                
            self.logger.info(f"Certificates for relay {relay.name} verified")
        
        self.logger.info("All certificates verified successfully")
        return True

    def run_all_tests(self) -> None:
        """Run all TLS tests for each relay"""
        if not self.verify_certificate_setup():
            self.logger.error("Certificate verification failed. Aborting tests.")
            return
    
        results: Dict[str, Dict[str, bool]] = {}
        
        for relay in self.relays:
            relay_results = {}
            self.logger.info(f"\n=== Testing Relay {relay.name} ({relay.port}) ===")
            
            # Test upload state
            relay_results['upload_state'] = self.test_relay_upload_state(relay)
            
            # Test download states
            relay_results['download_states'] = self.test_relay_download_states(relay)
            
            # Test heartbeat
            relay_results['heartbeat'] = self.test_relay_heartbeat(relay)
            
            # Test continuous operation
            relay_results['continuous_operation'] = self.test_relay_continuous_operation(relay, duration=30)
            
            results[relay.name] = relay_results

        # Print summary
        self.logger.info("\n=== Test Results ===")
        for relay_name, relay_results in results.items():
            self.logger.info(f"\nRelay: {relay_name}")
            for test_name, result in relay_results.items():
                self.logger.info(f"{test_name}: {'✓ PASS' if result else '✗ FAIL'}")

    def cleanup(self, signum: Optional[int] = None, frame: Optional[Any] = None) -> None:
        """Cleanup function to handle proper shutdown"""
        self.logger.info("\nCleaning up...")
        for relay in self.relays:
            try:
                relay.shutdown()
            except Exception as e:
                self.logger.error(f"Error shutting down relay {relay.name}: {e}")
        sys.exit(0)

if __name__ == "__main__":
    tester = RelayTLSTest()
    try:
        tester.run_all_tests()
    finally:
        tester.cleanup()