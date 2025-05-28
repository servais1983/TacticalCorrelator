#!/usr/bin/env python3
"""
TacticalCorrelator CLI - Interface en ligne de commande

Fournit une interface complète pour utiliser TacticalCorrelator
depuis la ligne de commande.
"""

import click
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.panel import Panel

from .core.correlator import TacticalCorrelator
from .utils.export_utils import ExportManager
from .config.settings import Settings

console = Console()

@click.group()
@click.version_option()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, 
              help='Enable verbose output')
@click.pass_context
def main(ctx, config, verbose):
    """TacticalCorrelator - Advanced Forensic Correlation Framework"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    
    if verbose:
        console.print("[green]TacticalCorrelator CLI v1.0.0[/green]")

@main.command()
@click.option('--case', '-c', required=True, 
              help='Case name for the analysis')
@click.option('--evidence', '-e', required=True, type=click.Path(exists=True),
              help='Path to evidence directory')
@click.option('--output', '-o', required=True, type=click.Path(),
              help='Output directory for results')
@click.option('--sources', '-s', multiple=True,
              help='Specific sources to analyze (evtx, dns, proxy, etc.)')
@click.option('--threshold', '-t', type=float, default=0.7,
              help='Anomaly detection threshold (0.0-1.0)')
@click.option('--timeline', is_flag=True,
              help='Generate intelligent timeline')
@click.option('--graph', is_flag=True,
              help='Build relationship graph')
@click.option('--ml', is_flag=True,
              help='Enable ML analysis')
@click.pass_context
def analyze(ctx, case, evidence, output, sources, threshold, timeline, graph, ml):
    """Analyze evidence and generate correlation report"""
    
    config_path = ctx.obj.get('config')
    verbose = ctx.obj.get('verbose')
    
    console.print(Panel(f"[bold blue]Analyzing Case: {case}[/bold blue]"))
    
    try:
        # Initialisation du correlator
        correlator = TacticalCorrelator(config_path)
        
        # Scan des artefacts
        evidence_path = Path(evidence)
        evidence_files = scan_evidence_directory(evidence_path, sources)
        
        if verbose:
            console.print(f"Found {len(evidence_files)} evidence files")
            for source_type, files in evidence_files.items():
                console.print(f"  {source_type}: {len(files)} files")
        
        # Analyse asynchrone
        results = asyncio.run(
            correlator.analyze_case(
                case_name=case,
                evidence_paths=evidence_files,
                output_dir=output,
                generate_timeline=timeline,
                build_graph=graph,
                enable_ml=ml,
                anomaly_threshold=threshold
            )
        )
        
        # Affichage des résultats
        display_results(results, verbose)
        
        console.print(f"[green]Analysis complete! Results saved to: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        sys.exit(1)

@main.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True),
              help='Input results file')
@click.option('--format', '-f', 
              type=click.Choice(['json', 'csv', 'stix', 'misp', 'yara']),
              default='json', help='Export format')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path')
def export(input, format, output):
    """Export analysis results to various formats"""
    
    console.print(f"[blue]Exporting results to {format.upper()} format[/blue]")
    
    try:
        export_manager = ExportManager()
        
        # Chargement des résultats
        with open(input, 'r') as f:
            results = json.load(f)
        
        # Export
        output_path = export_manager.export_results(
            results, format, output
        )
        
        console.print(f"[green]Results exported to: {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        sys.exit(1)

@main.command()
@click.option('--host', default='localhost', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--dev', is_flag=True, help='Enable development mode')
def serve(host, port, dev):
    """Start the web interface"""
    
    console.print(f"[blue]Starting TacticalCorrelator Web Interface[/blue]")
    console.print(f"Server: http://{host}:{port}")
    
    try:
        import uvicorn
        from .web.app import create_app
        
        app = create_app()
        uvicorn.run(
            app, 
            host=host, 
            port=port, 
            reload=dev,
            log_level="info" if dev else "warning"
        )
        
    except ImportError:
        console.print("[red]Web interface dependencies not installed[/red]")
        console.print("Install with: pip install tactical-correlator[viz]")
        sys.exit(1)

def scan_evidence_directory(evidence_path: Path, sources: List[str]) -> Dict[str, List[str]]:
    """Scan evidence directory and categorize files"""
    
    evidence_files = {
        'windows': [],
        'linux': [],
        'network': [],
        'edr': []
    }
    
    # Mapping des extensions vers les catégories
    extensions_map = {
        '.evtx': 'windows',
        '.pf': 'windows',
        '.log': 'network',
        '.pcap': 'network',
        '.json': 'edr',
        '.csv': 'edr'
    }
    
    for file_path in evidence_path.rglob('*'):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if ext in extensions_map:
                category = extensions_map[ext]
                if not sources or category in sources:
                    evidence_files[category].append(str(file_path))
    
    return evidence_files

def display_results(results: Dict, verbose: bool = False):
    """Display analysis results in a formatted table"""
    
    # Tableau des événements prioritaires
    if 'high_priority_events' in results:
        table = Table(title="High Priority Events")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Source", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Score", style="red")
        
        for event in results['high_priority_events'][:10]:  # Top 10
            table.add_row(
                event.get('timestamp', 'Unknown'),
                event.get('source', 'Unknown'),
                event.get('description', 'No description')[:50] + '...',
                f"{event.get('priority_score', 0):.2f}"
            )
        
        console.print(table)
    
    # Statistiques générales
    if verbose and 'stats' in results:
        stats = results['stats']
        console.print(f"\n[bold]Analysis Statistics:[/bold]")
        console.print(f"  Total events processed: {stats.get('total_events', 0)}")
        console.print(f"  Correlations found: {stats.get('correlations', 0)}")
        console.print(f"  Anomalies detected: {stats.get('anomalies', 0)}")
        console.print(f"  Analysis duration: {stats.get('duration', 0):.2f}s")

if __name__ == '__main__':
    main()