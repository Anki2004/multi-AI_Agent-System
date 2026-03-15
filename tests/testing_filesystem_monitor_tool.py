import pytest
import os
import tempfile
from datetime import datetime, timedelta
from tools.filesystem_monitor_tool import FileSystemMonitorTool
from unittest.mock import patch
tool = FileSystemMonitorTool()
def test_critical_file_modification():
    with tempfile.NamedTemporaryFile(delete = False) as f:
        f.write(b"fake passwd content")
        tmp_path = f.name
    with patch("tools.filesystem_monitor_tool.CRITICAL_FILES",[tmp_path]):
        result = tool._run(hours_back = "24")

    assert result["total_fs_threats"] > 0
    assert result["detections"][0]["threat_type"] == "critical_system_file_modified"
    assert result["detections"][0]["severity"] == "CRITICAL"

    os.unlink(tmp_path)

def test_critical_file_not_modified():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"fake passwd content")
        tmp_path = f.name

    old_time = (datetime.now()-timedelta(hours=48)).timestamp()
    os.utime(tmp_path, (old_time, old_time))
    with patch("tools.filesystem_monitor_tool.CRITICAL_FILES", [tmp_path]):
        result = tool._run(hours_back = "24")
    assert result["total_fs_threats"] == 0

    os.unlink(tmp_path)

def test_critical_file_not_found():
    with patch("tools.filesystem_monitor_tool.CRITICAL_FILES",["/nonexistent/file"]):
        result = tool._run(hours_back ="24")
    assert result["total_fs_threats"] == 0


    