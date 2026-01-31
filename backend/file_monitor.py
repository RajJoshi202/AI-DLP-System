"""
File system monitoring service for AI-DLP System.
Monitors directories for file changes and scans for sensitive data.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

# File content extractors
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None


class FileContentExtractor:
    """Extract text content from various file types."""
    
    @staticmethod
    def extract_txt(file_path: Path) -> str:
        """Extract content from TXT file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    @staticmethod
    def extract_pdf(file_path: Path) -> str:
        """Extract content from PDF file."""
        if PyPDF2 is None:
            return "PyPDF2 not installed"
        
        try:
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"
                return text
        except Exception as e:
            return f"Error reading PDF: {str(e)}"
    
    @staticmethod
    def extract_docx(file_path: Path) -> str:
        """Extract content from DOCX file."""
        if docx is None:
            return "python-docx not installed"
        
        try:
            doc = docx.Document(file_path)
            text = "\n".join([para.text for para in doc.paragraphs])
            return text
        except Exception as e:
            return f"Error reading DOCX: {str(e)}"
    
    @staticmethod
    def extract_csv(file_path: Path) -> str:
        """Extract content from CSV file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            return f"Error reading CSV: {str(e)}"
    
    @classmethod
    def extract(cls, file_path: Path) -> Optional[str]:
        """
        Extract content from file based on extension.
        
        Args:
            file_path: Path to file
        
        Returns:
            Extracted text content or None if unsupported
        """
        suffix = file_path.suffix.lower()
        
        extractors = {
            ".txt": cls.extract_txt,
            ".pdf": cls.extract_pdf,
            ".docx": cls.extract_docx,
            ".doc": cls.extract_docx,
            ".csv": cls.extract_csv,
            ".log": cls.extract_txt,
            ".md": cls.extract_txt,
        }
        
        extractor = extractors.get(suffix)
        if extractor:
            return extractor(file_path)
        
        return None


class DLPFileHandler(FileSystemEventHandler):
    """File system event handler for DLP monitoring."""
    
    def __init__(self, scan_callback: Callable[[Path], None]):
        """
        Initialize handler.
        
        Args:
            scan_callback: Callback function to scan files
        """
        self.scan_callback = scan_callback
        self.supported_extensions = {".txt", ".pdf", ".docx", ".doc", ".csv", ".log", ".md"}
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix.lower() in self.supported_extensions:
                self.scan_callback(file_path)
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification events."""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix.lower() in self.supported_extensions:
                self.scan_callback(file_path)


class FileMonitor:
    """File system monitor for DLP."""
    
    def __init__(self):
        """Initialize file monitor."""
        self.observer: Optional[Observer] = None
        self.monitored_paths: List[str] = []
        self.scan_callback: Optional[Callable] = None
        self.is_running = False
    
    def start(self, directory: str, scan_callback: Callable[[Path], None], recursive: bool = True):
        """
        Start monitoring a directory.
        
        Args:
            directory: Directory path to monitor
            scan_callback: Callback function for scanning files
            recursive: Whether to monitor subdirectories
        """
        if self.is_running:
            self.stop()
        
        self.scan_callback = scan_callback
        self.observer = Observer()
        
        event_handler = DLPFileHandler(scan_callback)
        self.observer.schedule(event_handler, directory, recursive=recursive)
        self.observer.start()
        
        self.monitored_paths = [directory]
        self.is_running = True
    
    def stop(self):
        """Stop monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        
        self.is_running = False
        self.monitored_paths = []
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status."""
        return {
            "is_running": self.is_running,
            "monitored_paths": self.monitored_paths,
            "observer_alive": self.observer.is_alive() if self.observer else False,
        }
    
    @staticmethod
    def scan_directory(directory: str, scan_callback: Callable[[Path], None]):
        """
        Scan all existing files in a directory (one-time scan).
        
        Args:
            directory: Directory path to scan
            scan_callback: Callback function for scanning files
        """
        dir_path = Path(directory)
        if not dir_path.exists() or not dir_path.is_dir():
            return
        
        supported_extensions = {".txt", ".pdf", ".docx", ".doc", ".csv", ".log", ".md"}
        
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in supported_extensions:
                scan_callback(file_path)


# Global monitor instance
_monitor_instance: Optional[FileMonitor] = None


def get_monitor() -> FileMonitor:
    """Get global file monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = FileMonitor()
    return _monitor_instance
