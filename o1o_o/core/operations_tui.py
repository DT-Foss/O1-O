"""
Multi-Window Operations Console (TUI).

Pure curses terminal UI — no external dependencies.
5 panels: network graph, credentials, alerts, actions log, command.
Real-time event listener, keyboard input, color-coded host status.
"""
import curses
import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


class Panel:
    """A single TUI panel with its own window and buffer."""

    def __init__(self, name: str, win, title: str = '',
                 color_pair: int = 0):
        self.name = name
        self.win = win
        self.title = title
        self.color_pair = color_pair
        self.lines: List[Tuple[str, int]] = []  # (text, color_pair)
        self.scroll_offset = 0
        self.max_lines = 500  # ring buffer size

    def add_line(self, text: str, color_pair: int = 0):
        """Add a line to the panel buffer."""
        self.lines.append((text, color_pair))
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]

    def clear_lines(self):
        self.lines = []
        self.scroll_offset = 0

    def scroll_up(self, n: int = 1):
        self.scroll_offset = max(0, self.scroll_offset - n)

    def scroll_down(self, n: int = 1):
        max_y, _ = self.win.getmaxyx()
        visible = max_y - 2
        max_scroll = max(0, len(self.lines) - visible)
        self.scroll_offset = min(max_scroll, self.scroll_offset + n)

    def scroll_to_bottom(self):
        max_y, _ = self.win.getmaxyx()
        visible = max_y - 2
        self.scroll_offset = max(0, len(self.lines) - visible)

    def render(self):
        """Render the panel contents."""
        try:
            self.win.erase()
            self.win.box()
            max_y, max_x = self.win.getmaxyx()

            # Title
            if self.title:
                title_str = f' {self.title} '
                try:
                    self.win.addstr(0, 2, title_str,
                                    curses.A_BOLD | curses.color_pair(self.color_pair))
                except curses.error:
                    pass

            # Content
            visible_lines = max_y - 2
            start = self.scroll_offset
            end = start + visible_lines

            for i, (text, cp) in enumerate(self.lines[start:end]):
                row = i + 1
                if row >= max_y - 1:
                    break
                # Truncate to panel width
                display_text = text[:max_x - 3]
                try:
                    self.win.addstr(row, 1, f' {display_text}',
                                    curses.color_pair(cp))
                except curses.error:
                    pass

            # Scroll indicator
            if len(self.lines) > visible_lines:
                pct = int(100 * self.scroll_offset /
                          max(1, len(self.lines) - visible_lines))
                try:
                    self.win.addstr(max_y - 1, max_x - 8,
                                    f' {pct:3d}% ',
                                    curses.A_DIM)
                except curses.error:
                    pass

            self.win.noutrefresh()
        except curses.error:
            pass


class OperationsTUI:
    """Multi-panel terminal UI for live operation monitoring."""

    # Panel layout definitions (proportional)
    PANEL_DEFS = {
        'network': {
            'row': 0.0, 'col': 0.0, 'height': 0.5, 'width': 0.5,
            'title': 'NETWORK', 'color': 1,
        },
        'credentials': {
            'row': 0.0, 'col': 0.5, 'height': 0.5, 'width': 0.5,
            'title': 'CREDENTIALS', 'color': 2,
        },
        'alerts': {
            'row': 0.5, 'col': 0.0, 'height': 0.25, 'width': 0.5,
            'title': 'ALERTS', 'color': 3,
        },
        'actions': {
            'row': 0.5, 'col': 0.5, 'height': 0.25, 'width': 0.5,
            'title': 'ACTIONS LOG', 'color': 4,
        },
        'command': {
            'row': 0.75, 'col': 0.0, 'height': 0.25, 'width': 1.0,
            'title': 'COMMAND', 'color': 5,
        },
    }

    # Color pair definitions
    COLOR_PAIRS = {
        1: (curses.COLOR_GREEN, -1),    # compromised/network
        2: (curses.COLOR_YELLOW, -1),   # credentials
        3: (curses.COLOR_RED, -1),      # alerts/burned
        4: (curses.COLOR_CYAN, -1),     # info/actions
        5: (curses.COLOR_MAGENTA, -1),  # command/critical
        6: (curses.COLOR_WHITE, -1),    # default bright
    }

    # Host status icons and colors
    HOST_STATUS = {
        'compromised':        ('●', 1),  # green
        'credentials_found':  ('◐', 2),  # yellow
        'burned':             ('✗', 3),  # red
        'discovered':         ('○', 4),  # cyan
        'scanning':           ('◌', 5),  # magenta
    }

    # Keybindings
    KEYBINDINGS = {
        'q': 'quit',
        ':': 'command_mode',
        'k': 'kill_operation',
        'r': 'refresh',
        'j': 'scroll_down',
        'k_alt': 'scroll_up',      # handled via panel focus
        'h': 'help',
        '1': 'focus_network',
        '2': 'focus_credentials',
        '3': 'focus_alerts',
        '4': 'focus_actions',
        '5': 'focus_command',
        'tab': 'cycle_focus',
    }

    def __init__(self, ops_db=None, daemon_client=None):
        self.ops_db = ops_db
        self.daemon = daemon_client
        self.running = False
        self.panels: Dict[str, Panel] = {}
        self.focused_panel = 'network'
        self.command_buffer = ''
        self.command_history: List[str] = []
        self.command_handler: Optional[Callable] = None
        self.event_handlers: Dict[str, Callable] = {}
        self._lock = threading.Lock()

    def set_command_handler(self, handler: Callable):
        """Set callback for command input."""
        self.command_handler = handler

    def register_event_handler(self, event_type: str, handler: Callable):
        """Register handler for specific event types."""
        self.event_handlers[event_type] = handler

    # ─── Panel Management ─────────────────────────────

    def create_panels(self, stdscr) -> Dict[str, Panel]:
        """Create all panels based on terminal size."""
        max_y, max_x = stdscr.getmaxyx()
        panels = {}

        for name, config in self.PANEL_DEFS.items():
            h = max(3, int(max_y * config['height']))
            w = max(10, int(max_x * config['width']))
            y = int(max_y * config['row'])
            x = int(max_x * config['col'])

            # Clamp to screen bounds
            if y + h > max_y:
                h = max_y - y
            if x + w > max_x:
                w = max_x - x

            try:
                win = curses.newwin(h, w, y, x)
                panels[name] = Panel(name, win, config['title'],
                                     config['color'])
            except curses.error:
                pass

        return panels

    def resize_panels(self, stdscr):
        """Recreate panels after terminal resize."""
        self.panels = self.create_panels(stdscr)

    # ─── Host Rendering ───────────────────────────────

    def render_host(self, host: dict) -> Tuple[str, int]:
        """Render a host entry for the network panel."""
        status = host.get('status', 'discovered')
        icon, color = self.HOST_STATUS.get(status, ('?', 0))
        ip = host.get('ip', '?.?.?.?')
        hostname = host.get('hostname', '')[:20]
        os_fp = host.get('os_fingerprint', '?')[:12]
        arch = host.get('arch', '')[:6]
        line = f'{icon} {ip:15s} {hostname:20s} [{os_fp:12s}] {arch}'
        return (line, color)

    def render_credential(self, cred: dict) -> Tuple[str, int]:
        """Render a credential entry for the credentials panel."""
        ctype = cred.get('cred_type', '?')[:12]
        username = cred.get('username', '')[:20]
        domain = cred.get('domain', '')[:15]
        source = cred.get('source', '')[:15]
        value_preview = cred.get('value', '')[:10]
        if len(cred.get('value', '')) > 10:
            value_preview += '...'
        line = f'{ctype:12s} {username:20s} {domain:15s} {value_preview:13s} [{source}]'
        return (line, 2)

    def render_alert(self, alert: dict) -> Tuple[str, int]:
        """Render an alert entry."""
        severity = alert.get('severity', 'info')
        timestamp = alert.get('timestamp', '')[:19]
        message = alert.get('message', '')
        color = {'critical': 3, 'warning': 2, 'info': 4}.get(severity, 0)
        icon = {'critical': '!!!', 'warning': ' ! ', 'info': ' i '}.get(severity, '   ')
        line = f'[{icon}] {timestamp} {message}'
        return (line, color)

    def render_action(self, action: dict) -> Tuple[str, int]:
        """Render an action log entry."""
        timestamp = action.get('timestamp', '')[:19]
        action_type = action.get('type', '?')[:12]
        target = action.get('target', '')[:20]
        result = action.get('result', '')[:20]
        color = 1 if action.get('success') else 3
        line = f'{timestamp} {action_type:12s} {target:20s} → {result}'
        return (line, color)

    # ─── Data Loading ─────────────────────────────────

    def load_hosts(self, hosts: List[dict]):
        """Load host data into the network panel."""
        panel = self.panels.get('network')
        if not panel:
            return
        with self._lock:
            panel.clear_lines()
            for host in hosts:
                text, color = self.render_host(host)
                panel.add_line(text, color)

    def load_credentials(self, creds: List[dict]):
        """Load credential data into the credentials panel."""
        panel = self.panels.get('credentials')
        if not panel:
            return
        with self._lock:
            panel.clear_lines()
            for cred in creds:
                text, color = self.render_credential(cred)
                panel.add_line(text, color)

    def add_alert(self, alert: dict):
        """Add an alert to the alerts panel."""
        panel = self.panels.get('alerts')
        if not panel:
            return
        with self._lock:
            text, color = self.render_alert(alert)
            panel.add_line(text, color)
            panel.scroll_to_bottom()

    def add_action(self, action: dict):
        """Add an action to the actions log panel."""
        panel = self.panels.get('actions')
        if not panel:
            return
        with self._lock:
            text, color = self.render_action(action)
            panel.add_line(text, color)
            panel.scroll_to_bottom()

    def add_command_output(self, text: str, color: int = 4):
        """Add output to the command panel."""
        panel = self.panels.get('command')
        if not panel:
            return
        with self._lock:
            panel.add_line(text, color)
            panel.scroll_to_bottom()

    # ─── Command Processing ───────────────────────────

    def process_command(self, cmd: str) -> str:
        """Process a command entered in the command panel."""
        cmd = cmd.strip()
        if not cmd:
            return ''

        self.command_history.append(cmd)
        parts = cmd.split()
        verb = parts[0].lower()

        if verb == 'help':
            return (
                'Commands: hosts, creds, alerts, clear <panel>, '
                'abort <host>, status, quit'
            )
        elif verb == 'clear':
            target = parts[1] if len(parts) > 1 else 'command'
            if target in self.panels:
                self.panels[target].clear_lines()
                return f'Cleared {target}'
            return f'Unknown panel: {target}'
        elif verb == 'quit' or verb == 'exit':
            self.running = False
            return 'Shutting down...'
        elif verb == 'status':
            panel_counts = {k: len(v.lines) for k, v in self.panels.items()}
            return f'Panels: {json.dumps(panel_counts)}'
        elif verb == 'focus':
            target = parts[1] if len(parts) > 1 else ''
            if target in self.panels:
                self.focused_panel = target
                return f'Focused: {target}'
            return f'Unknown panel: {target}'
        elif self.command_handler:
            return self.command_handler(cmd)
        else:
            return f'Unknown command: {cmd}'

    # ─── Status Bar ───────────────────────────────────

    def render_status_bar(self, stdscr):
        """Render the bottom status bar."""
        max_y, max_x = stdscr.getmaxyx()
        host_count = len(self.panels.get('network', Panel('', None)).lines)
        cred_count = len(self.panels.get('credentials', Panel('', None)).lines)
        alert_count = len(self.panels.get('alerts', Panel('', None)).lines)

        status = (
            f' FORGE OPS | Hosts: {host_count} | Creds: {cred_count} | '
            f'Alerts: {alert_count} | Focus: {self.focused_panel} | '
            f'q=quit :=cmd 1-5=panels'
        )
        try:
            stdscr.addstr(max_y - 1, 0, status[:max_x - 1],
                          curses.A_REVERSE | curses.color_pair(6))
        except curses.error:
            pass

    # ─── Main Loop ────────────────────────────────────

    def run(self):
        """Start the TUI."""
        self.running = True
        curses.wrapper(self._main)

    def _main(self, stdscr):
        """Main curses loop."""
        # Setup
        curses.use_default_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)

        for pair_id, (fg, bg) in self.COLOR_PAIRS.items():
            try:
                curses.init_pair(pair_id, fg, bg)
            except curses.error:
                pass

        self.panels = self.create_panels(stdscr)

        # Add welcome message to command panel
        self.add_command_output('FORGE Operations Console initialized', 5)
        self.add_command_output('Type :help for commands', 4)

        while self.running:
            try:
                key = stdscr.getch()
            except curses.error:
                key = -1

            if key == -1:
                pass
            elif key == ord('q'):
                self.running = False
            elif key == ord(':'):
                self._enter_command_mode(stdscr)
            elif key == ord('r'):
                self.resize_panels(stdscr)
            elif key == ord('j'):
                focused = self.panels.get(self.focused_panel)
                if focused:
                    focused.scroll_down()
            elif key == ord('k'):
                focused = self.panels.get(self.focused_panel)
                if focused:
                    focused.scroll_up()
            elif key == 9:  # Tab
                panel_names = list(self.panels.keys())
                try:
                    idx = panel_names.index(self.focused_panel)
                    self.focused_panel = panel_names[(idx + 1) % len(panel_names)]
                except ValueError:
                    self.focused_panel = panel_names[0] if panel_names else ''
            elif key in (ord('1'), ord('2'), ord('3'), ord('4'), ord('5')):
                panel_names = list(self.panels.keys())
                idx = key - ord('1')
                if idx < len(panel_names):
                    self.focused_panel = panel_names[idx]
            elif key == curses.KEY_RESIZE:
                self.resize_panels(stdscr)

            # Render all panels
            with self._lock:
                for panel in self.panels.values():
                    panel.render()

            # Status bar
            self.render_status_bar(stdscr)
            curses.doupdate()
            curses.napms(100)

    def _enter_command_mode(self, stdscr):
        """Enter command input mode."""
        curses.curs_set(1)
        cmd_panel = self.panels.get('command')
        if not cmd_panel:
            curses.curs_set(0)
            return

        max_y, max_x = cmd_panel.win.getmaxyx()
        self.command_buffer = ''

        while True:
            # Show prompt
            try:
                cmd_panel.win.addstr(max_y - 1, 1,
                                     ':' + self.command_buffer + ' ' * (max_x - len(self.command_buffer) - 3),
                                     curses.A_BOLD)
                cmd_panel.win.refresh()
            except curses.error:
                pass

            try:
                key = stdscr.getch()
            except curses.error:
                key = -1

            if key == -1:
                curses.napms(50)
                continue
            elif key == 27:  # ESC
                break
            elif key in (10, 13):  # Enter
                if self.command_buffer:
                    self.add_command_output(f'> {self.command_buffer}', 6)
                    result = self.process_command(self.command_buffer)
                    if result:
                        self.add_command_output(result, 4)
                    self.command_buffer = ''
                break
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self.command_buffer = self.command_buffer[:-1]
            elif 32 <= key <= 126:
                self.command_buffer += chr(key)

        curses.curs_set(0)

    # ─── Event Listener Thread ────────────────────────

    def start_event_listener(self, poll_interval: float = 1.0):
        """Start background thread that polls for events."""
        thread = threading.Thread(
            target=self._event_loop,
            args=(poll_interval,),
            daemon=True)
        thread.start()
        return thread

    def _event_loop(self, poll_interval: float):
        """Background event polling loop."""
        while self.running:
            try:
                if self.ops_db:
                    # Poll for new events from ops DB
                    # Subclass or callback would populate panels
                    pass
                if self.daemon:
                    # Poll daemon for updates
                    pass
            except Exception:
                pass
            time.sleep(poll_interval)

    # ─── Programmatic Panel Population ────────────────

    def populate_demo_data(self):
        """Populate panels with demo data for testing."""
        # Network panel
        demo_hosts = [
            {'ip': '10.0.0.1', 'hostname': 'dc01.corp.local', 'status': 'compromised',
             'os_fingerprint': 'Win2019', 'arch': 'x64'},
            {'ip': '10.0.0.5', 'hostname': 'web01.corp.local', 'status': 'credentials_found',
             'os_fingerprint': 'Ubuntu 22', 'arch': 'x64'},
            {'ip': '10.0.0.10', 'hostname': 'db01.corp.local', 'status': 'discovered',
             'os_fingerprint': 'CentOS 8', 'arch': 'x64'},
            {'ip': '10.0.0.20', 'hostname': 'mail.corp.local', 'status': 'scanning',
             'os_fingerprint': 'Exchange', 'arch': 'x64'},
            {'ip': '10.0.0.50', 'hostname': 'honeypot-01', 'status': 'burned',
             'os_fingerprint': 'Unknown', 'arch': '?'},
        ]
        self.load_hosts(demo_hosts)

        # Credentials panel
        demo_creds = [
            {'cred_type': 'ntlm_hash', 'username': 'admin', 'domain': 'CORP',
             'value': 'aad3b435...', 'source': 'dc01'},
            {'cred_type': 'password', 'username': 'svc_sql', 'domain': 'CORP',
             'value': 'Summer2024!', 'source': 'web01'},
            {'cred_type': 'ssh_key', 'username': 'root', 'domain': 'db01',
             'value': '-----BEGIN', 'source': 'web01'},
        ]
        self.load_credentials(demo_creds)

        # Alerts
        demo_alerts = [
            {'severity': 'critical', 'timestamp': '2026-02-17 08:32:15',
             'message': 'EDR detected on dc01 — CrowdStrike Falcon'},
            {'severity': 'warning', 'timestamp': '2026-02-17 08:33:01',
             'message': 'Canary token found in admin credentials'},
            {'severity': 'info', 'timestamp': '2026-02-17 08:34:00',
             'message': 'Credential spray complete — 3/50 valid'},
        ]
        for alert in demo_alerts:
            self.add_alert(alert)

        # Actions
        demo_actions = [
            {'timestamp': '2026-02-17 08:30:00', 'type': 'recon',
             'target': '10.0.0.0/24', 'result': '5 hosts found', 'success': True},
            {'timestamp': '2026-02-17 08:31:00', 'type': 'exploit',
             'target': '10.0.0.1', 'result': 'ntlm hash dumped', 'success': True},
            {'timestamp': '2026-02-17 08:32:00', 'type': 'lateral',
             'target': '10.0.0.50', 'result': 'BURNED — honeypot', 'success': False},
        ]
        for action in demo_actions:
            self.add_action(action)

    # ─── Export ───────────────────────────────────────

    def export_panels(self) -> dict:
        """Export all panel contents as JSON-serializable dict."""
        export = {}
        for name, panel in self.panels.items():
            export[name] = {
                'title': panel.title,
                'line_count': len(panel.lines),
                'lines': [(text, cp) for text, cp in panel.lines],
            }
        return export

    # ─── Status ───────────────────────────────────────

    def status(self) -> dict:
        return {
            'running': self.running,
            'panels': list(self.PANEL_DEFS.keys()),
            'focused_panel': self.focused_panel,
            'command_history_size': len(self.command_history),
            'keybindings': list(self.KEYBINDINGS.keys()),
            'color_pairs': len(self.COLOR_PAIRS),
            'host_statuses': list(self.HOST_STATUS.keys()),
        }
