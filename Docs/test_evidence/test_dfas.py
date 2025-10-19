"""
Unit Tests for Digital Forensics Agent System (DFAS)
Tests core functionality including hashing, file detection, and evidence handling
"""

import unittest
import os
import tempfile
import shutil
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import sys

# Import DFAS modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import DFAS

class TestDatabaseManager(unittest.TestCase):
    """Test database initialization and operations"""
    
    def setUp(self):
        """Create temporary database for testing"""
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        self.db_manager = DFAS.DatabaseManager(self.test_db.name)
    
    def tearDown(self):
        """Clean up test database"""
        if os.path.exists(self.test_db.name):
            os.unlink(self.test_db.name)
    
    def test_database_initialization(self):
        """Test that database tables are created correctly"""
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        
        # Check evidence_records table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_records'")
        self.assertIsNotNone(cursor.fetchone(), "evidence_records table should exist")
        
        # Check chain_of_custody table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chain_of_custody'")
        self.assertIsNotNone(cursor.fetchone(), "chain_of_custody table should exist")
        
        conn.close()
    
    def test_insert_evidence_record(self):
        """Test inserting evidence record into database"""
        test_record = DFAS.EvidenceRecord(
            id="test-001",
            case_id="case-001",
            file_path="/test/file.txt",
            rel_path="file.txt",
            size=1024,
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            accessed_time=datetime.now(timezone.utc),
            owner="test_user",
            file_type="text/plain",
            extension=".txt",
            sha256="abc123",
            yara_tags=[],
            collected_by="test_agent",
            collected_at=datetime.now(timezone.utc),
            notes="Test record"
        )
        
        self.db_manager.insert_evidence(test_record)
        
        # Verify insertion
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_records WHERE id=?", ("test-001",))
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(result, "Record should be inserted")
        self.assertEqual(result[0], "test-001", "Record ID should match")

class TestProcessingAgent(unittest.TestCase):
    """Test file processing functionality"""
    
    def setUp(self):
        """Create temporary test files and database"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        # Create test files
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, 'w') as f:
            f.write("Test content for hashing")
        
        self.db_manager = DFAS.DatabaseManager(self.test_db.name)
        self.config = {'case_id': 'test-case', 'collected_by': 'test_agent'}
        self.agent = DFAS.ProcessingAgent(self.db_manager, self.config)
    
    def tearDown(self):
        """Clean up test files and database"""
        shutil.rmtree(self.test_dir)
        if os.path.exists(self.test_db.name):
            os.unlink(self.test_db.name)
    
    def test_sha256_calculation(self):
        """Test SHA-256 hash calculation accuracy"""
        calculated_hash = self.agent.calculate_sha256(self.test_file)
        
        # Verify hash is not empty
        self.assertTrue(calculated_hash, "Hash should not be empty")
        self.assertEqual(len(calculated_hash), 64, "SHA-256 hash should be 64 characters")
        
        # Verify hash consistency
        second_hash = self.agent.calculate_sha256(self.test_file)
        self.assertEqual(calculated_hash, second_hash, "Hash should be consistent")
        
        # Verify against known hash
        expected_hash = hashlib.sha256(b"Test content for hashing").hexdigest()
        self.assertEqual(calculated_hash, expected_hash, "Hash should match expected value")
    
    def test_file_type_detection(self):
        """Test file type detection functionality"""
        file_type = self.agent.get_file_type(self.test_file)
        
        self.assertIsNotNone(file_type, "File type should not be None")
        self.assertIn("text", file_type.lower(), "Should detect as text file")
    
    def test_metadata_extraction(self):
        """Test complete metadata extraction process"""
        record = self.agent.extract_metadata(self.test_file)
        
        self.assertIsNotNone(record, "Should return evidence record")
        self.assertEqual(record.file_path, str(Path(self.test_file).absolute()))
        self.assertGreater(record.size, 0, "File size should be greater than 0")
        self.assertEqual(len(record.sha256), 64, "SHA-256 hash should be 64 characters")
        self.assertEqual(record.extension, ".txt")

class TestDiscoveryAgent(unittest.TestCase):
    """Test file discovery functionality"""
    
    def setUp(self):
        """Create test directory structure"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        # Create test files with various extensions
        self.test_files = []
        extensions = ['.txt', '.pdf', '.docx', '.jpg', '.exe']
        for ext in extensions:
            file_path = os.path.join(self.test_dir, f"test{ext}")
            with open(file_path, 'w') as f:
                f.write(f"Test content {ext}")
            self.test_files.append(file_path)
        
        self.db_manager = DFAS.DatabaseManager(self.test_db.name)
        self.config = {
            'scan_paths': [self.test_dir],
            'target_extensions': ['.txt', '.pdf', '.docx', '.jpg'],
            'exclude_paths': [],
            'max_file_size': 100 * 1024 * 1024
        }
        self.agent = DFAS.DiscoveryAgent(self.db_manager, self.config)
        self.file_queue = DFAS.queue.Queue()
        self.agent.set_file_queue(self.file_queue)
    
    def tearDown(self):
        """Clean up test directory"""
        shutil.rmtree(self.test_dir)
        if os.path.exists(self.test_db.name):
            os.unlink(self.test_db.name)
    
    def test_file_discovery(self):
        """Test that discovery agent finds correct files"""
        discovered_count = self.agent.discover_files()
        
        # Should find 4 files (.txt, .pdf, .docx, .jpg) but not .exe
        self.assertEqual(discovered_count, 4, "Should discover 4 matching files")
        self.assertEqual(self.file_queue.qsize(), 4, "Queue should contain 4 files")
    
    def test_extension_filtering(self):
        """Test that file extension filtering works correctly"""
        self.agent.discover_files()
        
        found_extensions = []
        while not self.file_queue.empty():
            file_path = self.file_queue.get()
            found_extensions.append(Path(file_path).suffix)
        
        # Should not find .exe file
        self.assertNotIn('.exe', found_extensions, "Should not discover .exe files")
        
        # Should find target extensions
        for ext in ['.txt', '.pdf', '.docx', '.jpg']:
            self.assertIn(ext, found_extensions, f"Should discover {ext} files")
    
    def test_file_size_filtering(self):
        """Test that files exceeding max size are excluded"""
        # Create a large file
        large_file = os.path.join(self.test_dir, "large.txt")
        with open(large_file, 'wb') as f:
            f.write(b'0' * (150 * 1024 * 1024))  # 150MB
        
        # Update config with smaller max size
        self.agent.max_file_size = 100 * 1024 * 1024  # 100MB
        
        discovered_count = self.agent.discover_files()
        
        # Verify large file was excluded
        queue_contents = []
        while not self.file_queue.empty():
            queue_contents.append(self.file_queue.get())
        
        self.assertNotIn(large_file, queue_contents, "Large file should be excluded")

class TestPackagingAgent(unittest.TestCase):
    """Test evidence packaging functionality"""
    
    def setUp(self):
        """Create test database with sample data"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        self.db_manager = DFAS.DatabaseManager(self.test_db.name)
        
        # Insert sample evidence record
        test_record = DFAS.EvidenceRecord(
            id="pkg-test-001",
            case_id="pkg-case-001",
            file_path="/test/file.txt",
            rel_path="file.txt",
            size=1024,
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            accessed_time=datetime.now(timezone.utc),
            owner="test_user",
            file_type="text/plain",
            extension=".txt",
            sha256="abc123def456",
            yara_tags=[],
            collected_by="test_agent",
            collected_at=datetime.now(timezone.utc),
            notes="Test packaging"
        )
        self.db_manager.insert_evidence(test_record)
        
        self.config = {
            'case_id': 'pkg-case-001',
            'output_dir': self.test_dir
        }
        self.agent = DFAS.PackagingAgent(self.db_manager, self.config)
    
    def tearDown(self):
        """Clean up test files"""
        shutil.rmtree(self.test_dir)
        if os.path.exists(self.test_db.name):
            os.unlink(self.test_db.name)
    
    def test_csv_export(self):
        """Test CSV report generation"""
        csv_path = self.agent.export_to_csv()
        
        self.assertTrue(os.path.exists(csv_path), "CSV file should be created")
        
        # Verify CSV content
        with open(csv_path, 'r') as f:
            content = f.read()
            self.assertIn('pkg-test-001', content, "CSV should contain test record ID")
            self.assertIn('abc123def456', content, "CSV should contain hash")
    
    def test_json_export(self):
        """Test JSON report generation"""
        json_path = self.agent.export_to_json()
        
        self.assertTrue(os.path.exists(json_path), "JSON file should be created")
        
        # Verify JSON content
        import json
        with open(json_path, 'r') as f:
            data = json.load(f)
            self.assertIsInstance(data, list, "JSON should be a list")
            self.assertGreater(len(data), 0, "JSON should contain records")
            self.assertEqual(data[0]['id'], 'pkg-test-001', "Should contain test record")
    
    def test_package_creation(self):
        """Test evidence package creation"""
        package_path = self.agent.create_package()
        
        self.assertTrue(os.path.exists(package_path), "Package file should be created")
        self.assertTrue(package_path.endswith('.zip'), "Package should be ZIP format")
        
        # Verify package hash was recorded
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM chain_of_custody WHERE action='package_created'")
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(result, "Chain of custody entry should exist")

class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflow"""
    
    def setUp(self):
        """Create test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        # Create test files
        for i in range(3):
            file_path = os.path.join(self.test_dir, f"evidence_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Evidence content {i}")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if os.path.exists(self.test_db.name):
            os.unlink(self.test_db.name)
    
    def test_end_to_end_workflow(self):
        """Test complete evidence collection workflow"""
        config = {
            'case_id': 'integration-test',
            'scan_paths': [self.test_dir],
            'target_extensions': ['.txt'],
            'exclude_paths': [],
            'max_file_size': 100 * 1024 * 1024,
            'output_dir': self.test_dir,
            'collected_by': 'test_agent'
        }
        
        db_manager = DFAS.DatabaseManager(self.test_db.name)
        
        # Discovery phase
        discovery = DFAS.DiscoveryAgent(db_manager, config)
        file_queue = DFAS.queue.Queue()
        discovery.set_file_queue(file_queue)
        discovered = discovery.discover_files()
        
        self.assertEqual(discovered, 3, "Should discover 3 test files")
        
        # Processing phase
        processing = DFAS.ProcessingAgent(db_manager, config)
        processing.set_file_queue(file_queue)
        
        while not file_queue.empty():
            file_path = file_queue.get()
            record = processing.extract_metadata(file_path)
            self.assertIsNotNone(record, f"Should process {file_path}")
            db_manager.insert_evidence(record)
        
        # Packaging phase
        packaging = DFAS.PackagingAgent(db_manager, config)
        package_path = packaging.create_package()
        
        self.assertTrue(os.path.exists(package_path), "Package should be created")
        
        # Verify database has all records
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM evidence_records")
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertEqual(count, 3, "Database should contain 3 evidence records")

def run_tests_with_report():
    """Run all tests and generate detailed report"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseManager))
    suite.addTests(loader.loadTestsFromTestCase(TestProcessingAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestDiscoveryAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestPackagingAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests_with_report()
    sys.exit(0 if success else 1)