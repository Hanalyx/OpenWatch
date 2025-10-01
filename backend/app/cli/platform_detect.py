#!/usr/bin/env python3
"""
Platform Detection CLI Tool
Command-line interface for platform detection and compatibility checking
"""
import asyncio
import click
import json
from typing import List

from backend.app.services.platform_detection_service import PlatformDetectionService
from backend.app.models.unified_rule_models import Platform, PlatformVersionRange


@click.group()
def cli():
    """Platform Detection and Compatibility CLI"""
    pass


@cli.command()
@click.option('--format', '-f', default='text', type=click.Choice(['json', 'text']), help='Output format')
@click.option('--refresh', '-r', is_flag=True, help='Force refresh cached information')
async def detect(format: str, refresh: bool):
    """Detect comprehensive platform information"""
    
    service = PlatformDetectionService()
    
    try:
        click.echo("Detecting platform information...")
        
        platform_info = await service.detect_platform_info(force_refresh=refresh)
        output = await service.export_platform_info(format)
        
        click.echo("\nPlatform Information:")
        click.echo("=" * 50)
        click.echo(output)
        
    except Exception as e:
        click.echo(f"Error detecting platform: {e}", err=True)


@cli.command()
@click.option('--platform', '-p', required=True, type=click.Choice([p.value for p in Platform]), help='Target platform')
@click.option('--min-version', '--min', help='Minimum version required')
@click.option('--max-version', '--max', help='Maximum version supported')
@click.option('--architecture', '-a', help='Required architecture')
@click.option('--exclude', '-e', multiple=True, help='Excluded versions')
@click.option('--capability', '-c', multiple=True, help='Required capabilities')
async def check(platform: str, min_version: str, max_version: str, architecture: str, exclude: List[str], capability: List[str]):
    """Check compatibility with platform requirements"""
    
    service = PlatformDetectionService()
    
    try:
        # Create platform version range
        platform_range = PlatformVersionRange(
            platform=Platform(platform),
            min_version=min_version,
            max_version=max_version,
            excluded_versions=list(exclude) if exclude else [],
            architecture=architecture
        )
        
        click.echo(f"Checking compatibility with {platform}...")
        if min_version:
            click.echo(f"  Minimum version: {min_version}")
        if max_version:
            click.echo(f"  Maximum version: {max_version}")
        if architecture:
            click.echo(f"  Architecture: {architecture}")
        if exclude:
            click.echo(f"  Excluded versions: {', '.join(exclude)}")
        if capability:
            click.echo(f"  Required capabilities: {', '.join(capability)}")
        
        # Check compatibility
        result = await service.check_compatibility(
            platform_range,
            required_capabilities=list(capability) if capability else None
        )
        
        click.echo("\nCompatibility Result:")
        click.echo("=" * 30)
        click.echo(f"Compatible: {click.style('YES' if result.is_compatible else 'NO', fg='green' if result.is_compatible else 'red')}")
        click.echo(f"Platform Match: {result.platform_match}")
        click.echo(f"Version Match: {result.version_match}")
        click.echo(f"Architecture Match: {result.architecture_match}")
        click.echo(f"Excluded Version: {result.excluded_version}")
        click.echo(f"Compatibility Score: {result.compatibility_score:.2f}")
        
        if result.missing_capabilities:
            click.echo(f"\nMissing Capabilities:")
            for cap in result.missing_capabilities:
                click.echo(f"  - {cap}")
        
        if result.warnings:
            click.echo(f"\nWarnings:")
            for warning in result.warnings:
                click.echo(f"  - {warning}")
        
    except Exception as e:
        click.echo(f"Error checking compatibility: {e}", err=True)


@cli.command()
@click.argument('rule_file', type=click.Path(exists=True))
async def check_rule(rule_file: str):
    """Check compatibility for a unified rule file"""
    
    service = PlatformDetectionService()
    
    try:
        # Load rule file
        with open(rule_file, 'r') as f:
            rule_data = json.load(f)
        
        rule_id = rule_data.get('rule_id', 'unknown')
        click.echo(f"Checking compatibility for rule: {rule_id}")
        
        # Get supported platforms from rule
        supported_platforms = rule_data.get('supported_platforms', [])
        if not supported_platforms:
            click.echo("No supported platforms found in rule file", err=True)
            return
        
        # Create platform ranges
        platform_ranges = []
        for platform_data in supported_platforms:
            platform_range = PlatformVersionRange(
                platform=Platform(platform_data['platform']),
                min_version=platform_data.get('min_version'),
                max_version=platform_data.get('max_version'),
                excluded_versions=platform_data.get('excluded_versions', []),
                architecture=platform_data.get('architecture')
            )
            platform_ranges.append(platform_range)
        
        # Check compatibility for all platforms
        results = await service.get_compatible_platforms(platform_ranges)
        
        click.echo(f"\nCompatibility Results for {len(platform_ranges)} platforms:")
        click.echo("=" * 60)
        
        for platform_range, result in results:
            status_color = 'green' if result.is_compatible else 'red'
            status_text = 'COMPATIBLE' if result.is_compatible else 'INCOMPATIBLE'
            
            click.echo(f"\n{platform_range.platform.value}:")
            click.echo(f"  Status: {click.style(status_text, fg=status_color)}")
            click.echo(f"  Score: {result.compatibility_score:.2f}")
            
            if platform_range.min_version:
                click.echo(f"  Min Version: {platform_range.min_version}")
            if platform_range.max_version:
                click.echo(f"  Max Version: {platform_range.max_version}")
            if platform_range.architecture:
                click.echo(f"  Architecture: {platform_range.architecture}")
            
            if result.warnings:
                click.echo(f"  Warnings: {', '.join(result.warnings)}")
        
        # Summary
        compatible_count = sum(1 for _, result in results if result.is_compatible)
        click.echo(f"\nSummary: {compatible_count}/{len(results)} platforms compatible")
        
    except Exception as e:
        click.echo(f"Error checking rule compatibility: {e}", err=True)


@cli.command()
@click.option('--capability', '-c', multiple=True, help='Filter by capability')
@click.option('--package-manager', '-p', multiple=True, help='Filter by package manager')
@click.option('--security-module', '-s', multiple=True, help='Filter by security module')
async def capabilities(capability: List[str], package_manager: List[str], security_module: List[str]):
    """Show system capabilities and filter options"""
    
    service = PlatformDetectionService()
    
    try:
        platform_info = await service.detect_platform_info()
        
        click.echo("System Capabilities:")
        click.echo("=" * 30)
        
        # Show all capabilities
        click.echo("Available Capabilities:")
        for cap in platform_info.capabilities:
            status = "✓" if not capability or cap.value in capability else " "
            click.echo(f"  {status} {cap.value}")
        
        click.echo(f"\nPackage Managers:")
        for pm in platform_info.package_managers:
            status = "✓" if not package_manager or pm in package_manager else " "
            click.echo(f"  {status} {pm}")
        
        click.echo(f"\nSecurity Modules:")
        for sm in platform_info.security_modules:
            status = "✓" if not security_module or any(s in sm for s in security_module) else " "
            click.echo(f"  {status} {sm}")
        
        # Filter results
        if capability or package_manager or security_module:
            click.echo(f"\nFilter Results:")
            
            # Check capability filters
            if capability:
                platform_caps = [cap.value for cap in platform_info.capabilities]
                missing_caps = [cap for cap in capability if cap not in platform_caps]
                if missing_caps:
                    click.echo(f"Missing capabilities: {', '.join(missing_caps)}")
                else:
                    click.echo("All required capabilities available")
            
            # Check package manager filters
            if package_manager:
                missing_pm = [pm for pm in package_manager if pm not in platform_info.package_managers]
                if missing_pm:
                    click.echo(f"Missing package managers: {', '.join(missing_pm)}")
                else:
                    click.echo("All required package managers available")
            
            # Check security module filters
            if security_module:
                available_sm = ' '.join(platform_info.security_modules).lower()
                missing_sm = [sm for sm in security_module if sm.lower() not in available_sm]
                if missing_sm:
                    click.echo(f"Missing security modules: {', '.join(missing_sm)}")
                else:
                    click.echo("All required security modules available")
        
    except Exception as e:
        click.echo(f"Error getting capabilities: {e}", err=True)


@cli.command()
async def summary():
    """Show a comprehensive platform summary"""
    
    service = PlatformDetectionService()
    
    try:
        platform_info = await service.detect_platform_info()
        
        click.echo("Platform Summary")
        click.echo("=" * 50)
        click.echo(f"Platform: {platform_info.platform.value}")
        click.echo(f"Version: {platform_info.version}")
        click.echo(f"Architecture: {platform_info.architecture}")
        click.echo(f"Kernel: {platform_info.kernel_version}")
        click.echo(f"Hostname: {platform_info.hostname}")
        click.echo(f"Distribution: {platform_info.distribution}")
        
        if platform_info.codename:
            click.echo(f"Codename: {platform_info.codename}")
        
        click.echo(f"\nSystem Information:")
        click.echo(f"Init System: {platform_info.init_system or 'Unknown'}")
        
        if platform_info.virtualization_type:
            click.echo(f"Virtualization: {platform_info.virtualization_type}")
        
        if platform_info.container_runtime:
            click.echo(f"Container Runtime: {platform_info.container_runtime}")
        
        if platform_info.desktop_environment:
            click.echo(f"Desktop Environment: {platform_info.desktop_environment}")
        
        if platform_info.shell:
            click.echo(f"Shell: {platform_info.shell}")
        
        if platform_info.python_version:
            click.echo(f"Python Version: {platform_info.python_version}")
        
        click.echo(f"\nCapabilities ({len(platform_info.capabilities)}):")
        for cap in sorted([cap.value for cap in platform_info.capabilities]):
            click.echo(f"  ✓ {cap}")
        
        click.echo(f"\nPackage Managers ({len(platform_info.package_managers)}):")
        for pm in sorted(platform_info.package_managers):
            click.echo(f"  ✓ {pm}")
        
        if platform_info.security_modules:
            click.echo(f"\nSecurity Modules ({len(platform_info.security_modules)}):")
            for sm in platform_info.security_modules:
                click.echo(f"  ✓ {sm}")
        
    except Exception as e:
        click.echo(f"Error getting platform summary: {e}", err=True)


def main():
    """Main entry point for async CLI commands"""
    import inspect
    
    # Get the command from click context
    ctx = click.get_current_context()
    command_name = ctx.info_name
    
    # Map command names to async functions
    async_commands = {
        'detect': detect,
        'check': check,
        'check-rule': check_rule,
        'capabilities': capabilities,
        'summary': summary
    }
    
    if command_name in async_commands:
        # Get the parameters from context
        params = ctx.params
        # Run the async command
        asyncio.run(async_commands[command_name](**params))
    else:
        # Run synchronous commands normally
        cli()


if __name__ == '__main__':
    cli()