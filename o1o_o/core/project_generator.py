"""
Project Generator — Generate multi-file Python projects from intent

Features:
1. Detect project type from intent
2. Generate multi-file projects from templates
3. Analyze existing project structure (imports, modules, entry points)
4. Generate code that integrates with existing project
5. Dynamic project planning via ProjectPlanner
"""
# Dependencies: project_planner
# Depended by: none (leaf module)


import os
import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

class ProjectGenerator:
    """Generate multi-file Python projects from intent"""

    # Project templates
    TEMPLATES = {
        'flask_api': {
            'files': {
                'app.py': 'flask_basic',
                'models.py': 'sqlalchemy_model',
                'config.py': '# Configuration file\nDEBUG = True\nPORT = 5000',
                'requirements.txt': 'flask\nsqlalchemy\npsycopg2-binary'
            },
            'keywords': {'flask', 'api', 'web app', 'rest'}
        },
        'cli_tool': {
            'files': {
                'main.py': 'argparse_basic',
                'utils.py': '# Utility functions\ndef helper():\n    pass',
                'requirements.txt': 'rich\nclick'
            },
            'keywords': {'cli', 'tool', 'command line', 'argparse'}
        },
        'data_pipeline': {
            'files': {
                'pipeline.py': 'numpy_array',
                'extractors.py': 'pandas_read_csv',
                'transformers.py': 'numpy_stats',
                'requirements.txt': 'numpy\npandas\nscikit-learn'
            },
            'keywords': {'pipeline', 'data', 'numpy', 'pandas', 'analytics'}
        },
        'web_scraper': {
            'files': {
                'scraper.py': 'requests_get',
                'parser.py': 'bs4_parse',
                'storage.py': 'csv_write',
                'requirements.txt': 'requests\nbeautifulsoup4'
            },
            'keywords': {'scraper', 'crawl', 'scraping', 'harvest'}
        },
    }

    def __init__(self, fragments_dir: Path, knowledge_engine: Any, code_assembler: Any):
        self.fragments_dir = Path(fragments_dir)
        self.knowledge = knowledge_engine
        self.assembler = code_assembler
        from o1o_o.core.project_planner import ProjectPlanner
        self.planner = ProjectPlanner(self.knowledge)

    def detect_project_type(self, intent: Dict[str, Any]) -> Optional[str]:
        """
        V8: Detect if intent is complex enough for ProjectPlanner.
        If it contains 'and', 'then', or multiple domain entities, it's a project.
        """
        raw = intent.get('raw', '').lower()
        if any(conj in raw for conj in [' and ', ' then ', ' also ', ' thereafter ']):
            return "dynamic_system"
            
        # Fallback to templates
        tokens = set(intent.get('tokens', []))
        for p_type, config in self.TEMPLATES.items():
            if any(kw in raw for kw in config['keywords']):
                return p_type
            if any(token in config['keywords'] for token in tokens):
                return p_type
        
        return None

    def generate_project(self, p_type: str, intent: Dict[str, Any]) -> Dict[str, str]:
        """Generate complete project files using either templates or dynamic planner"""
        if p_type == "dynamic_system":
            return self._generate_dynamic_project(intent)
            
        if p_type not in self.TEMPLATES:
            return {}

        template = self.TEMPLATES[p_type]
        project_files = {}

        for filename, content_key in template['files'].items():
            # If content_key is a fragment key, assemble it
            if content_key in self.assembler.fragments or any(content_key in f for f in self.assembler.fragments):
                # We need an inference chain for the assembler
                chain = self.knowledge.infer({'entities': [{'matched': content_key}], 'tokens': [content_key]})
                if chain:
                    project_files[filename] = self.assembler.assemble(chain, intent)
                else:
                    project_files[filename] = f"# Placeholder for {content_key}"
            else:
                project_files[filename] = content_key

        return project_files

    def _generate_dynamic_project(self, intent: Dict[str, Any]) -> Dict[str, str]:
        """V8: Use ProjectPlanner to design and assemble a custom multi-file system"""
        plan = self.planner.plan(intent)
        project_files = {}
        
        # Meta-file: Project Manifest for the user
        project_files["manifest.json"] = str(plan['manifest'])
        
        for agent in plan['agents']:
            agent_intent = {
                "raw": agent['intent_raw'],
                "entities": intent.get('entities', []), # Shared entities
                "mode": "BUILD"
            }
            
            # 1. Infer path for this agent
            chains = self.knowledge.infer(agent_intent, top_k=1)
            if chains:
                # 2. Assemble script with project context (Manifest-Sync)
                script = self.assembler.assemble(chains[0], agent_intent, project_context=plan)
                filename = f"{agent['name']}.py"
                project_files[filename] = script
            else:
                project_files[f"{agent['name']}.py"] = f"# No path found for: {agent['intent_raw']}"
                
        # Add Launcher and Cron
        if 'launcher_script' in plan:
            project_files['run_all.sh'] = plan['launcher_script']
        if 'cron_job' in plan:
            project_files['crontab.txt'] = plan['cron_job']
            
        return project_files

    def save_project(self, project_files: Dict[str, str], target_dir: Path):
        """Save project files to directory"""
        target_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in project_files.items():
            with open(target_dir / filename, 'w') as f:
                f.write(content)
        print(f"Generated project in {target_dir}")

    # --- Multi-file project awareness ---

    def analyze_project(self, project_dir: Path = None) -> Dict[str, Any]:
        """Analyze existing project structure for integration-aware generation"""
        if project_dir is None:
            project_dir = Path.cwd()

        analysis = {
            'root': str(project_dir),
            'python_files': [],
            'modules': {},
            'imports': set(),
            'entry_points': [],
            'functions': {},
            'classes': {},
            'config_files': [],
            'has_tests': False,
            'has_requirements': False,
            'framework': None,
        }

        # Scan Python files
        for py_file in sorted(project_dir.rglob('*.py')):
            # Skip venv, __pycache__, .git
            rel = py_file.relative_to(project_dir)
            parts = rel.parts
            if any(p in {'venv', '__pycache__', '.git', 'node_modules', '.tox'} for p in parts):
                continue

            rel_str = str(rel)
            analysis['python_files'].append(rel_str)

            # Detect entry points
            if py_file.name in ('main.py', 'app.py', 'run.py', 'manage.py', 'cli.py'):
                analysis['entry_points'].append(rel_str)

            # Detect test files
            if py_file.name.startswith('test_') or 'tests/' in rel_str:
                analysis['has_tests'] = True

            # Parse AST for imports, functions, classes
            try:
                source = py_file.read_text(errors='replace')
                tree = ast.parse(source)

                file_info = {
                    'imports': [],
                    'functions': [],
                    'classes': [],
                }

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            file_info['imports'].append(alias.name)
                            analysis['imports'].add(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            file_info['imports'].append(node.module)
                            analysis['imports'].add(node.module)
                    elif isinstance(node, ast.FunctionDef):
                        file_info['functions'].append(node.name)
                        analysis['functions'][node.name] = rel_str
                    elif isinstance(node, ast.ClassDef):
                        file_info['classes'].append(node.name)
                        analysis['classes'][node.name] = rel_str

                analysis['modules'][rel_str] = file_info

            except (SyntaxError, UnicodeDecodeError):
                analysis['modules'][rel_str] = {'imports': [], 'functions': [], 'classes': []}

        # Detect config files
        for config_name in ['requirements.txt', 'setup.py', 'pyproject.toml',
                           '.env', 'config.py', 'settings.py', 'Makefile',
                           'Dockerfile', 'docker-compose.yml']:
            if (project_dir / config_name).exists():
                analysis['config_files'].append(config_name)

        analysis['has_requirements'] = 'requirements.txt' in analysis['config_files']

        # Detect framework
        imports_lower = {i.lower() for i in analysis['imports']}
        if 'flask' in imports_lower:
            analysis['framework'] = 'flask'
        elif 'django' in imports_lower:
            analysis['framework'] = 'django'
        elif 'fastapi' in imports_lower:
            analysis['framework'] = 'fastapi'

        # Convert set to list for JSON serialization
        analysis['imports'] = sorted(analysis['imports'])

        return analysis

    def generate_integration_code(self, intent: Dict[str, Any],
                                   project_analysis: Dict[str, Any]) -> Dict[str, str]:
        """Generate code that integrates with an existing project structure"""
        files = {}
        raw = intent.get('raw', '').lower()
        framework = project_analysis.get('framework')

        # If adding a new endpoint to Flask project
        if framework == 'flask' and ('endpoint' in raw or 'route' in raw or 'api' in raw):
            files['new_route.py'] = self._generate_flask_route(intent, project_analysis)

        # If adding a new module
        elif 'module' in raw or 'add' in raw:
            module_name = self._extract_module_name(intent)
            files[f'{module_name}.py'] = self._generate_module(intent, project_analysis)

        # If adding tests
        elif 'test' in raw:
            files['test_new.py'] = self._generate_test_file(intent, project_analysis)

        return files

    def _generate_flask_route(self, intent: Dict[str, Any],
                               analysis: Dict[str, Any]) -> str:
        """Generate a Flask route that fits the project"""
        entities = [e['matched'] for e in intent.get('entities', [])]
        resource = entities[0] if entities else 'item'

        return f'''from flask import Blueprint, request, jsonify

bp = Blueprint('{resource}', __name__)

@bp.route('/api/{resource}', methods=['GET'])
def list_{resource}s():
    return jsonify([])

@bp.route('/api/{resource}', methods=['POST'])
def create_{resource}():
    data = request.get_json()
    return jsonify(data), 201

@bp.route('/api/{resource}/<int:id>', methods=['GET'])
def get_{resource}(id):
    return jsonify({{"id": id}})
'''

    def _generate_module(self, intent: Dict[str, Any],
                          analysis: Dict[str, Any]) -> str:
        """Generate a module that fits existing project patterns"""
        entities = [e['matched'] for e in intent.get('entities', [])]
        name = entities[0] if entities else 'utils'

        # Check existing coding style from analysis
        existing_classes = list(analysis.get('classes', {}).keys())

        return f'''"""
{name} module — generated by FORGE
"""

class {name.title()}:
    """Main class for {name} operations"""

    def __init__(self):
        pass

    def process(self, data):
        """Process data"""
        return data
'''

    def _generate_test_file(self, intent: Dict[str, Any],
                             analysis: Dict[str, Any]) -> str:
        """Generate a test file for existing modules"""
        functions = list(analysis.get('functions', {}).keys())[:5]

        test_lines = ['import pytest', '']
        for func in functions:
            source_file = analysis['functions'][func]
            module = source_file.replace('/', '.').replace('.py', '')
            test_lines.append(f'def test_{func}():')
            test_lines.append(f'    """Test {func}"""')
            test_lines.append(f'    # from {module} import {func}')
            test_lines.append(f'    assert True  # TODO: implement')
            test_lines.append('')

        return '\n'.join(test_lines)

    def _extract_module_name(self, intent: Dict[str, Any]) -> str:
        """Extract a module name from intent"""
        entities = [e['matched'] for e in intent.get('entities', [])]
        if entities:
            return entities[0].lower().replace(' ', '_')
        return 'new_module'
