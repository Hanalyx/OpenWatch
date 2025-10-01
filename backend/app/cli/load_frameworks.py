#!/usr/bin/env python3
"""
CLI tool for managing framework control definitions
Supports loading, validation, and management of compliance frameworks
"""
import asyncio
import click
import json
from pathlib import Path
from typing import Dict, Any

from backend.app.services.framework_loader_service import FrameworkLoaderService
from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition


@click.group()
def cli():
    """Framework Control Management CLI"""
    pass


@cli.command()
@click.option('--framework', '-f', help='Specific framework ID to load')
@click.option('--file', '-F', type=click.Path(exists=True), help='Specific file path to load')
@click.option('--dry-run', '-d', is_flag=True, help='Show what would be loaded without actually loading')
async def load(framework: str, file: str, dry_run: bool):
    """Load framework control definitions into MongoDB"""
    
    loader = FrameworkLoaderService()
    
    if file:
        # Load specific file
        file_path = Path(file)
        click.echo(f"Loading framework from: {file_path}")
        
        if dry_run:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                framework_info = data["framework_info"]
                control_count = len(data.get("controls", []))
                click.echo(f"Would load {control_count} controls for framework: {framework_info['name']}")
            except Exception as e:
                click.echo(f"Error reading file: {e}", err=True)
                return
        else:
            try:
                count = await loader.load_framework_from_file(file_path)
                click.echo(f"Successfully loaded {count} controls")
            except Exception as e:
                click.echo(f"Error loading framework: {e}", err=True)
                return
    
    elif framework:
        # Load specific framework
        framework_file = loader.framework_definitions_path / f"{framework}.json"
        if not framework_file.exists():
            click.echo(f"Framework file not found: {framework_file}", err=True)
            return
        
        click.echo(f"Loading framework: {framework}")
        
        if dry_run:
            try:
                with open(framework_file, 'r') as f:
                    data = json.load(f)
                control_count = len(data.get("controls", []))
                click.echo(f"Would load {control_count} controls for framework: {framework}")
            except Exception as e:
                click.echo(f"Error reading framework file: {e}", err=True)
                return
        else:
            try:
                count = await loader.load_framework_from_file(framework_file)
                click.echo(f"Successfully loaded {count} controls for {framework}")
            except Exception as e:
                click.echo(f"Error loading framework {framework}: {e}", err=True)
                return
    
    else:
        # Load all frameworks
        click.echo("Loading all available frameworks...")
        
        if dry_run:
            framework_files = [
                "nist_800_53_r5.json",
                "cis_v8.json",
                "srg_os.json", 
                "stig_rhel9.json",
                "iso_27001_2022.json",
                "pci_dss_v4.json"
            ]
            
            total_controls = 0
            for filename in framework_files:
                file_path = loader.framework_definitions_path / filename
                if file_path.exists():
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                        control_count = len(data.get("controls", []))
                        framework_name = data["framework_info"]["name"]
                        click.echo(f"  {filename}: {control_count} controls ({framework_name})")
                        total_controls += control_count
                    except Exception as e:
                        click.echo(f"  {filename}: Error reading file - {e}")
            
            click.echo(f"\nTotal controls that would be loaded: {total_controls}")
        else:
            try:
                results = await loader.load_all_frameworks()
                total_controls = sum(results.values())
                
                click.echo("Framework loading results:")
                for framework_id, count in results.items():
                    click.echo(f"  {framework_id}: {count} controls")
                
                click.echo(f"\nTotal controls loaded: {total_controls}")
            except Exception as e:
                click.echo(f"Error loading frameworks: {e}", err=True)
                return


@cli.command()
@click.option('--framework', '-f', help='Specific framework ID to validate')
async def validate(framework: str):
    """Validate framework integrity and cross-references"""
    
    loader = FrameworkLoaderService()
    
    if framework:
        # Validate specific framework
        click.echo(f"Validating framework: {framework}")
        
        try:
            result = await loader.validate_framework_integrity(framework)
            
            click.echo(f"Framework ID: {result['framework_id']}")
            click.echo(f"Database controls: {result['db_control_count']}")
            click.echo(f"File controls: {result['file_control_count']}")
            click.echo(f"Count match: {result['count_match']}")
            click.echo(f"Integrity score: {result['integrity_score']:.2f}")
            
            if result['missing_references']:
                click.echo("\nMissing cross-references:")
                for ref in result['missing_references']:
                    click.echo(f"  {ref['control']} -> {ref['missing_reference']}")
            else:
                click.echo("\nAll cross-references are valid")
                
        except Exception as e:
            click.echo(f"Error validating framework {framework}: {e}", err=True)
            return
    
    else:
        # Validate all frameworks
        click.echo("Validating all frameworks...")
        
        try:
            # Get all framework IDs from database
            framework_ids = await FrameworkControlDefinition.distinct("framework_id")
            
            overall_score = 0.0
            total_frameworks = len(framework_ids)
            
            for framework_id in framework_ids:
                result = await loader.validate_framework_integrity(framework_id)
                click.echo(f"\n{framework_id}:")
                click.echo(f"  Controls: {result['db_control_count']}")
                click.echo(f"  Integrity: {result['integrity_score']:.2f}")
                
                if result['missing_references']:
                    click.echo(f"  Missing refs: {len(result['missing_references'])}")
                
                overall_score += result['integrity_score']
            
            if total_frameworks > 0:
                avg_score = overall_score / total_frameworks
                click.echo(f"\nOverall integrity score: {avg_score:.2f}")
            
        except Exception as e:
            click.echo(f"Error validating frameworks: {e}", err=True)
            return


@cli.command()
async def summary():
    """Show summary of loaded frameworks"""
    
    loader = FrameworkLoaderService()
    
    try:
        summary = await loader.get_framework_summary()
        
        if not summary:
            click.echo("No frameworks currently loaded")
            return
        
        click.echo("Loaded Framework Summary:")
        click.echo("=" * 50)
        
        total_controls = 0
        for framework_id, info in summary.items():
            click.echo(f"\n{framework_id.upper()}")
            click.echo(f"  Name: {info['name']}")
            click.echo(f"  Version: {info['version']}")
            click.echo(f"  Organization: {info['organization']}")
            click.echo(f"  Controls: {info['control_count']}")
            click.echo(f"  Loaded: {info['loaded_at']}")
            total_controls += info['control_count']
        
        click.echo(f"\nTotal controls across all frameworks: {total_controls}")
        
    except Exception as e:
        click.echo(f"Error getting framework summary: {e}", err=True)
        return


@cli.command()
async def update_refs():
    """Update and verify cross-references between frameworks"""
    
    loader = FrameworkLoaderService()
    
    try:
        click.echo("Updating cross-references between frameworks...")
        
        results = await loader.update_cross_references()
        
        click.echo("Cross-reference update results:")
        total_updated = 0
        for framework_id, count in results.items():
            click.echo(f"  {framework_id}: {count} controls updated")
            total_updated += count
        
        click.echo(f"\nTotal controls updated: {total_updated}")
        
    except Exception as e:
        click.echo(f"Error updating cross-references: {e}", err=True)
        return


@cli.command()
@click.argument('query')
@click.option('--framework', '-f', help='Limit search to specific framework')
@click.option('--field', '-F', default='title', help='Field to search (title, description, family)')
async def search(query: str, framework: str, field: str):
    """Search for controls across frameworks"""
    
    try:
        # Build search filter
        search_filter = {}
        if framework:
            search_filter['framework_id'] = framework
        
        # Perform search based on field
        if field == 'title':
            controls = await FrameworkControlDefinition.find(
                FrameworkControlDefinition.title.contains(query, case_insensitive=True),
                **search_filter
            ).to_list()
        elif field == 'description':
            controls = await FrameworkControlDefinition.find(
                FrameworkControlDefinition.description.contains(query, case_insensitive=True),
                **search_filter
            ).to_list()
        elif field == 'family':
            controls = await FrameworkControlDefinition.find(
                FrameworkControlDefinition.family.contains(query, case_insensitive=True),
                **search_filter
            ).to_list()
        else:
            click.echo(f"Invalid field: {field}. Use title, description, or family", err=True)
            return
        
        if not controls:
            click.echo(f"No controls found matching '{query}' in {field}")
            return
        
        click.echo(f"Found {len(controls)} controls matching '{query}':")
        click.echo("=" * 60)
        
        for control in controls:
            click.echo(f"\n{control.framework_id} - {control.control_id}")
            click.echo(f"  Title: {control.title}")
            click.echo(f"  Family: {control.family}")
            if control.external_references:
                refs = ", ".join([f"{k}:{v}" for k, v in control.external_references.items() if v])
                click.echo(f"  References: {refs}")
        
    except Exception as e:
        click.echo(f"Error searching controls: {e}", err=True)
        return


def main():
    """Main entry point that handles async commands"""
    import inspect
    
    # Get the command from click context
    ctx = click.get_current_context()
    command = ctx.info_name
    
    # Find the corresponding async function
    async_commands = {
        'load': load,
        'validate': validate, 
        'summary': summary,
        'update-refs': update_refs,
        'search': search
    }
    
    if command in async_commands:
        # Run the async command
        asyncio.run(async_commands[command].callback(*ctx.params.values()))
    else:
        # Run synchronous commands normally
        cli()


if __name__ == '__main__':
    cli()