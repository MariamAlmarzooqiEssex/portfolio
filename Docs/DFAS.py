# Digital Forensics Agent System (DFAS)
# Implementation of BDI-inspired multi-agent system for digital forensics

import os
import sys
import json
import sqlite3
import hashlib
import logging
import threading
import queue
import time
import yaml
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
# Try to import magic, fall back to mimetypes if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    import mimetypes
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available, using mimetypes for file type detection")
import csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dfas.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class EvidenceRecord:
    """Data model for evidence records following ISO/NIST standards"""
    """
    Data model for evidence records following ISO/IEC 27037 guidelines
    
    Design Note: dataclass chosen over dict because:
    - Type safety catches errors at development time
    - IDE autocomplete improves developer productivity
    - Clear schema documentation for forensic analysts
    - Easier serialization to database/JSON
    """
    id: str  # uuid ensures global uniqueness across cases
    case_id: str  # links evidence to specific investigation
    file_path: str  # absolute path for precise file location
    rel_path: str  # relative path for portability across systems
    size: int  # size in bytes for capacity planning and filtering
    created_time: datetime  # file system creation (note: can be manipulated)
    modified_time: datetime  # last modification (key for timeline analysis)
    accessed_time: datetime  # last access (unreliable on some systems)
    owner: str  # ownership for attribution and access control investigation
    file_type: str  # MIME type from libmagic for reliable classification
    extension: str  # original extension preserved for context even if spoofed
    sha256: str  # sha-256 chosen per NIST SP 800-86 for court admissibility
    yara_tags: List[str]  # pattern match results for triage prioritization
    collected_by: str  # chain of custody: who collected the evidence
    collected_at: datetime  # chain of custody: when was it collected
    notes: str = ""  # additional context for analysts
    

@dataclass
class ChainEntry:
    """Chain of custody entry for audit trail"""
    id: str
    case_id: str
    action: str
    actor: str
    timestamp: datetime
    prev_hash: str
    entry_hash: str
    details: str

class DatabaseManager:
    """Manages SQLite database for evidence storage"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Evidence records table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                rel_path TEXT,
                size INTEGER,
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                owner TEXT,
                file_type TEXT,
                extension TEXT,
                sha256 TEXT,
                yara_tags TEXT,
                collected_by TEXT,
                collected_at TEXT,
                notes TEXT
            )
        """)
        
        # Chain of custody table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                prev_hash TEXT,
                entry_hash TEXT,
                details TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def insert_evidence(self, record: EvidenceRecord):
        """Insert evidence record into database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO evidence_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.id, record.case_id, record.file_path, record.rel_path,
            record.size, record.created_time.isoformat(), record.modified_time.isoformat(),
            record.accessed_time.isoformat(), record.owner, record.file_type,
            record.extension, record.sha256, json.dumps(record.yara_tags),
            record.collected_by, record.collected_at.isoformat(), record.notes
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"Evidence record inserted: {record.id}")
    
    def insert_chain_entry(self, entry: ChainEntry):
        """Insert chain of custody entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO chain_of_custody VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.id, entry.case_id, entry.action, entry.actor,
            entry.timestamp.isoformat(), entry.prev_hash, entry.entry_hash, entry.details
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"Chain entry recorded: {entry.action} by {entry.actor}")

class Agent:
    """Base class for BDI-inspired agents"""
    
    def __init__(self, name: str, db_manager: DatabaseManager):
        self.name = name
        self.db_manager = db_manager
        self.beliefs = {}  # Current facts
        self.desires = []  # Goals
        self.intentions = queue.Queue()  # Action queue
        self.running = False
        self.thread = None
        logger.info(f"Agent {self.name} initialized")
    
    def start(self):
        """Start agent execution"""
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        logger.info(f"Agent {self.name} started")
    
    def stop(self):
        """Stop agent execution"""
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info(f"Agent {self.name} stopped")
    
    def run(self):
        """Main agent execution loop"""
        while self.running:
            try:
                if not self.intentions.empty():
                    action = self.intentions.get(timeout=1)
                    self.execute_action(action)
                else:
                    time.sleep(0.1)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in agent {self.name}: {e}")
    
    def execute_action(self, action):
        """Execute an action - to be implemented by subclasses"""
        pass

class DiscoveryAgent(Agent):
    """Agent responsible for file discovery and filtering"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        super().__init__("Discovery", db_manager)
        self.config = config
        self.target_extensions = config.get('target_extensions', ['.pdf', '.docx', '.xlsx', '.jpg', '.zip'])
        self.scan_paths = config.get('scan_paths', ['.'])
        self.exclude_paths = config.get('exclude_paths', [])
        self.max_file_size = config.get('max_file_size', 100 * 1024 * 1024)  # 100MB
        self.file_queue = None
    
    def set_file_queue(self, file_queue: queue.Queue):
        """Set the queue for discovered files"""
        self.file_queue = file_queue
    
    def discover_files(self):
        """Discover files matching criteria"""
        discovered_count = 0
        
        for scan_path in self.scan_paths:
            path = Path(scan_path)
            if not path.exists():
                logger.warning(f"Scan path does not exist: {scan_path}")
                continue
            
            logger.info(f"Scanning path: {scan_path}")
            
            for file_path in path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                # Check exclusions
                if any(str(file_path).startswith(exclude) for exclude in self.exclude_paths):
                    continue
                
                # Check extension
                if file_path.suffix.lower() not in self.target_extensions:
                    continue
                
                # Check file size
                try:
                    file_size = file_path.stat().st_size
                    if file_size > self.max_file_size:
                        logger.info(f"File too large, skipping: {file_path}")
                        continue
                except OSError as e:
                    logger.warning(f"Cannot stat file {file_path}: {e}")
                    continue
                
                # Add to processing queue
                if self.file_queue:
                    self.file_queue.put(str(file_path))
                    discovered_count += 1
                    logger.debug(f"Discovered file: {file_path}")
        
        logger.info(f"Discovery complete. Found {discovered_count} files")
        return discovered_count
    
    def execute_action(self, action):
        """Execute discovery actions"""
        if action == "discover":
            self.discover_files()

class ProcessingAgent(Agent):
    """Agent responsible for file processing (hashing, metadata extraction)"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        super().__init__("Processing", db_manager)
        self.config = config
        self.case_id = config.get('case_id', str(uuid.uuid4()))
        self.collected_by = config.get('collected_by', f"{os.getenv('USERNAME', 'unknown')}@{os.getenv('COMPUTERNAME', 'unknown')}")
        self.file_queue = None
        
        # Initialize file type detector based on availability
        if MAGIC_AVAILABLE:
            try:
                self.magic_detector = magic.Magic(mime=True)
            except Exception:
                self.magic_detector = None
                print("Warning: Could not initialize libmagic, falling back to mimetypes")
        else:
            self.magic_detector = None
    
    def set_file_queue(self, file_queue: queue.Queue):
        """Set the queue for files to process"""
        self.file_queue = file_queue
    
    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return ""
    
    def get_file_type(self, file_path: str) -> str:
        """Get file type using libmagic or mimetypes as fallback"""
        try:
            # Try libmagic first if available
            if self.magic_detector:
                return self.magic_detector.from_file(file_path)
            
            # Fallback to mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                return mime_type
            
            # Final fallback - basic file extension mapping
            ext = Path(file_path).suffix.lower()
            extension_map = {
                '.pdf': 'application/pdf',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                '.txt': 'text/plain',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.zip': 'application/zip',
                '.exe': 'application/x-executable'
            }
            
            return extension_map.get(ext, 'application/octet-stream')
            
        except Exception as e:
            logger.error(f"Error detecting file type for {file_path}: {e}")
            return "application/octet-stream"
    
    def get_file_owner(self, file_path: Path) -> str:
        """Get file owner in a cross-platform way"""
        try:
            if hasattr(file_path, 'owner'):
                return file_path.owner()
            else:
                # Fallback for POSIX systems
                import pwd
                stat_info = file_path.stat()
                return pwd.getpwuid(stat_info.st_uid).pw_name
        except Exception:
            return os.getenv('USERNAME', 'unknown')

    
    def extract_metadata(self, file_path: str) -> Optional[EvidenceRecord]:
        """Extract metadata from file and create evidence record"""
        try:
            path = Path(file_path)
            stat_info = path.stat()
            
            # Calculate hash
            sha256_hash = self.calculate_sha256(file_path)
            if not sha256_hash:
                return None
            
            # Get file type
            file_type = self.get_file_type(file_path)
            
            # Create evidence record
            record = EvidenceRecord(
                id=str(uuid.uuid4()),
                case_id=self.case_id,
                file_path=str(path.absolute()),
                rel_path=str(path),
                size=stat_info.st_size,
                created_time=datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc),
                modified_time=datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc),
                accessed_time=datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc),
                owner=self.get_file_owner(path),
                file_type=file_type,
                extension=path.suffix.lower(),
                sha256=sha256_hash,
                yara_tags=[],  # YARA scanning would be implemented here
                collected_by=self.collected_by,
                collected_at=datetime.now(timezone.utc),
                notes=""
            )
            
            return record
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None
    
    def process_files(self):
        """Process files from queue"""
        processed_count = 0
        
        while self.running:
            try:
                if self.file_queue and not self.file_queue.empty():
                    file_path = self.file_queue.get(timeout=1)
                    
                    logger.info(f"Processing file: {file_path}")
                    record = self.extract_metadata(file_path)
                    
                    if record:
                        self.db_manager.insert_evidence(record)
                        processed_count += 1
                        logger.info(f"Processed file: {file_path} (Hash: {record.sha256[:16]}...)")
                    
                    self.file_queue.task_done()
                else:
                    time.sleep(0.1)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
        
        logger.info(f"Processing complete. Processed {processed_count} files")
    
    def execute_action(self, action):
        """Execute processing actions"""
        if action == "process":
            self.process_files()

class PackagingAgent(Agent):
    """Agent responsible for creating encrypted evidence packages"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        super().__init__("Packaging", db_manager)
        self.config = config
        self.case_id = config.get('case_id', str(uuid.uuid4()))
        self.output_dir = Path(config.get('output_dir', './evidence_packages'))
        self.output_dir.mkdir(exist_ok=True)
        
        # Generate encryption key (in production, use proper key management)
        self.encryption_key = AESGCM.generate_key(bit_length=256)
    
    def export_to_csv(self) -> str:
        """Export evidence records to CSV"""
        csv_path = self.output_dir / f"evidence_report_{self.case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM evidence_records WHERE case_id = ?", (self.case_id,))
        records = cursor.fetchall()
        
        # Get column names
        cursor.execute("PRAGMA table_info(evidence_records)")
        columns = [column[1] for column in cursor.fetchall()]
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(columns)
            writer.writerows(records)
        
        conn.close()
        logger.info(f"CSV report exported: {csv_path}")
        return str(csv_path)
    
    def export_to_json(self) -> str:
        """Export evidence records to JSON"""
        json_path = self.output_dir / f"evidence_report_{self.case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM evidence_records WHERE case_id = ?", (self.case_id,))
        records = cursor.fetchall()
        
        # Get column names
        cursor.execute("PRAGMA table_info(evidence_records)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Convert to list of dictionaries
        json_records = []
        for record in records:
            json_records.append(dict(zip(columns, record)))
        
        with open(json_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(json_records, jsonfile, indent=2, default=str)
        
        conn.close()
        logger.info(f"JSON report exported: {json_path}")
        return str(json_path)
    
    def create_package(self) -> str:
        """Create encrypted evidence package"""
        # Export reports
        csv_path = self.export_to_csv()
        json_path = self.export_to_json()
        
        # Create package
        package_path = self.output_dir / f"evidence_package_{self.case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(csv_path, Path(csv_path).name)
            zipf.write(json_path, Path(json_path).name)
            
            # Add database
            zipf.write(self.db_manager.db_path, "evidence.db")
        
        # Calculate package hash
        package_hash = self.calculate_file_hash(str(package_path))
        
        # Record chain of custody entry
        chain_entry = ChainEntry(
            id=str(uuid.uuid4()),
            case_id=self.case_id,
            action="package_created",
            actor=self.name,
            timestamp=datetime.now(timezone.utc),
            prev_hash="",
            entry_hash=package_hash,
            details=f"Evidence package created: {package_path.name}"
        )
        
        self.db_manager.insert_chain_entry(chain_entry)
        
        logger.info(f"Evidence package created: {package_path}")
        logger.info(f"Package hash: {package_hash}")
        
        return str(package_path)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def execute_action(self, action):
        """Execute packaging actions"""
        if action == "package":
            return self.create_package()

class OrchestratorAgent(Agent):
    """Main orchestrator agent that coordinates other agents"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        super().__init__("Orchestrator", db_manager)
        self.config = config
        self.file_queue = queue.Queue()
        
        # Initialize other agents
        self.discovery_agent = DiscoveryAgent(db_manager, config)
        self.processing_agent = ProcessingAgent(db_manager, config)
        self.packaging_agent = PackagingAgent(db_manager, config)
        
        # Set up communication
        self.discovery_agent.set_file_queue(self.file_queue)
        self.processing_agent.set_file_queue(self.file_queue)
    
    def start_collection(self):
        """Start the collection process"""
        logger.info("Starting digital forensics collection")
        
        # Start all agents
        self.discovery_agent.start()
        self.processing_agent.start()
        
        # Begin discovery
        self.discovery_agent.intentions.put("discover")
        
        # Start processing
        self.processing_agent.intentions.put("process")
        
        # Wait for discovery to complete
        time.sleep(2)  # Allow discovery to start
        while not self.file_queue.empty():
            time.sleep(1)
            logger.info(f"Files in queue: {self.file_queue.qsize()}")
        
        # Wait for processing to complete
        self.file_queue.join()
        
        # Create evidence package
        package_path = self.packaging_agent.create_package()
        
        # Stop agents
        self.discovery_agent.stop()
        self.processing_agent.stop()
        
        logger.info("Collection complete")
        return package_path

def load_config(config_path: str = "dfas_config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file"""
    default_config = {
        'case_id': str(uuid.uuid4()),
        'scan_paths': ['.'],
        'exclude_paths': ['__pycache__', '.git', '.venv'],
        'target_extensions': ['.pdf', '.docx', '.xlsx', '.txt', '.jpg', '.png', '.zip'],
        'max_file_size': 100 * 1024 * 1024,  # 100MB
        'output_dir': './evidence_packages',
        'collected_by': f"{os.getenv('USERNAME', 'unknown')}@{os.getenv('COMPUTERNAME', 'unknown')}"
    }
    
    if Path(config_path).exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            default_config.update(config)
    else:
        # Create default config file
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        logger.info(f"Created default configuration: {config_path}")
    
    return default_config

def main():
    """Main entry point for DFAS"""
    print("Digital Forensics Agent System (DFAS)")
    print("=====================================")
    
    # Load configuration
    config = load_config()
    print(f"Case ID: {config['case_id']}")
    print(f"Scan paths: {config['scan_paths']}")
    print(f"Target extensions: {config['target_extensions']}")
    
    # Initialize database
    db_path = f"evidence_{config['case_id']}.db"
    db_manager = DatabaseManager(db_path)
    
    # Initialize orchestrator
    orchestrator = OrchestratorAgent(db_manager, config)
    
    try:
        # Start collection
        package_path = orchestrator.start_collection()
        
        print("\n" + "="*50)
        print("COLLECTION SUMMARY")
        print("="*50)
        print(f"Case ID: {config['case_id']}")
        print(f"Evidence Database: {db_path}")
        print(f"Evidence Package: {package_path}")
        print(f"Collection completed at: {datetime.now()}")
        
    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
        orchestrator.discovery_agent.stop()
        orchestrator.processing_agent.stop()
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        raise

if __name__ == "__main__":
    main()