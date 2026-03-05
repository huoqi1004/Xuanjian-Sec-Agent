#!/usr/bin/env python3
"""
Improvement Tracker for Self-Improving Agents
Tracks and manages improvement initiatives
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import argparse

class ImprovementTracker:
    """Tracks improvement initiatives and progress"""
    
    def __init__(self, tracker_file=None):
        self.tracker_file = tracker_file or Path.home() / ".openclaw" / "workspace" / "memory" / "improvement_tracker.json"
        self.tracker_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize tracker if it doesn't exist
        self._init_tracker()
    
    def _init_tracker(self):
        """Initialize tracker file"""
        if not self.tracker_file.exists():
            tracker_data = {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "improvement_areas": {},
                "active_initiatives": [],
                "completed_initiatives": [],
                "metrics": {
                    "total_initiatives": 0,
                    "completed_initiatives": 0,
                    "success_rate": 0.0,
                    "avg_completion_time": 0
                }
            }
            
            self._save_tracker(tracker_data)
    
    def _load_tracker(self):
        """Load tracker data"""
        try:
            with open(self.tracker_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading tracker: {e}")
            return self._init_tracker()
    
    def _save_tracker(self, data):
        """Save tracker data"""
        try:
            data["last_updated"] = datetime.now().isoformat()
            with open(self.tracker_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving tracker: {e}")
    
    def create_initiative(self, area, description, goals, priority="medium"):
        """Create a new improvement initiative"""
        tracker_data = self._load_tracker()
        
        initiative = {
            "id": f"init_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "area": area,
            "description": description,
            "goals": goals if isinstance(goals, list) else [goals],
            "priority": priority,
            "status": "planned",
            "created": datetime.now().isoformat(),
            "start_date": None,
            "completion_date": None,
            "progress": 0,
            "notes": [],
            "metrics": {
                "time_spent": 0,
                "resources_used": [],
                "impact_score": 0
            }
        }
        
        tracker_data["active_initiatives"].append(initiative)
        tracker_data["metrics"]["total_initiatives"] += 1
        
        # Update improvement area
        if area not in tracker_data["improvement_areas"]:
            tracker_data["improvement_areas"][area] = {
                "total_initiatives": 0,
                "completed": 0,
                "success_rate": 0.0
            }
        
        tracker_data["improvement_areas"][area]["total_initiatives"] += 1
        
        self._save_tracker(tracker_data)
        
        print(f"Created initiative: {initiative['id']} - {description}")
        return initiative["id"]
    
    def start_initiative(self, initiative_id):
        """Start working on an initiative"""
        tracker_data = self._load_tracker()
        
        for initiative in tracker_data["active_initiatives"]:
            if initiative["id"] == initiative_id:
                initiative["status"] = "in_progress"
                initiative["start_date"] = datetime.now().isoformat()
                print(f"Started initiative: {initiative_id}")
                break
        
        self._save_tracker(tracker_data)
    
    def update_progress(self, initiative_id, progress, notes=None):
        """Update progress on an initiative"""
        tracker_data = self._load_tracker()
        
        for initiative in tracker_data["active_initiatives"]:
            if initiative["id"] == initiative_id:
                initiative["progress"] = max(0, min(100, progress))
                
                if notes:
                    note_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "progress": progress,
                        "notes": notes
                    }
                    initiative["notes"].append(note_entry)
                
                print(f"Updated {initiative_id}: {progress}% complete")
                break
        
        self._save_tracker(tracker_data)
    
    def complete_initiative(self, initiative_id, success=True, impact_score=0):
        """Mark an initiative as completed"""
        tracker_data = self._load_tracker()
        
        for i, initiative in enumerate(tracker_data["active_initiatives"]):
            if initiative["id"] == initiative_id:
                initiative["status"] = "completed_success" if success else "completed_partial"
                initiative["completion_date"] = datetime.now().isoformat()
                initiative["progress"] = 100
                initiative["metrics"]["impact_score"] = impact_score
                
                # Calculate time spent
                if initiative["start_date"]:
                    start = datetime.fromisoformat(initiative["start_date"])
                    end = datetime.now()
                    time_spent = (end - start).total_seconds() / 3600  # hours
                    initiative["metrics"]["time_spent"] = time_spent
                
                # Move to completed
                completed = tracker_data["active_initiatives"].pop(i)
                tracker_data["completed_initiatives"].append(completed)
                
                # Update metrics
                tracker_data["metrics"]["completed_initiatives"] += 1
                
                # Update area stats
                area = initiative["area"]
                if area in tracker_data["improvement_areas"]:
                    area_data = tracker_data["improvement_areas"][area]
                    area_data["completed"] += 1
                    if success:
                        # Update success rate
                        total = area_data["total_initiatives"]
                        completed = area_data["completed"]
                        area_data["success_rate"] = (completed / total * 100) if total > 0 else 0
                
                print(f"Completed initiative: {initiative_id} ({'success' if success else 'partial'})")
                break
        
        self._save_tracker(tracker_data)
    
    def get_initiative(self, initiative_id):
        """Get initiative details"""
        tracker_data = self._load_tracker()
        
        # Check active initiatives
        for initiative in tracker_data["active_initiatives"]:
            if initiative["id"] == initiative_id:
                return initiative
        
        # Check completed initiatives
        for initiative in tracker_data["completed_initiatives"]:
            if initiative["id"] == initiative_id:
                return initiative
        
        return None
    
    def list_initiatives(self, status=None, area=None):
        """List initiatives with optional filters"""
        tracker_data = self._load_tracker()
        
        initiatives = []
        
        # Add active initiatives
        for initiative in tracker_data["active_initiatives"]:
            if status and initiative["status"] != status:
                continue
            if area and initiative["area"] != area:
                continue
            initiatives.append(initiative)
        
        # Add completed initiatives
        for initiative in tracker_data["completed_initiatives"]:
            if status and initiative["status"] != status:
                continue
            if area and initiative["area"] != area:
                continue
            initiatives.append(initiative)
        
        return initiatives
    
    def get_improvement_areas(self):
        """Get all improvement areas with statistics"""
        tracker_data = self._load_tracker()
        return tracker_data["improvement_areas"]
    
    def get_metrics(self):
        """Get overall improvement metrics"""
        tracker_data = self._load_tracker()
        return tracker_data["metrics"]
    
    def generate_report(self, period_days=30):
        """Generate improvement report"""
        tracker_data = self._load_tracker()
        
        cutoff_date = datetime.now() - timedelta(days=period_days)
        
        report = {
            "period": f"Last {period_days} days",
            "generated": datetime.now().isoformat(),
            "summary": {
                "active_initiatives": len(tracker_data["active_initiatives"]),
                "completed_in_period": 0,
                "new_initiatives": 0,
                "avg_completion_time": 0
            },
            "top_areas": [],
            "recommendations": []
        }
        
        # Calculate completed in period
        completed_in_period = []
        for initiative in tracker_data["completed_initiatives"]:
            if initiative["completion_date"]:
                comp_date = datetime.fromisoformat(initiative["completion_date"])
                if comp_date >= cutoff_date:
                    completed_in_period.append(initiative)
        
        report["summary"]["completed_in_period"] = len(completed_in_period)
        
        # Calculate new initiatives
        for initiative in tracker_data["active_initiatives"]:
            if initiative["created"]:
                created_date = datetime.fromisoformat(initiative["created"])
                if created_date >= cutoff_date:
                    report["summary"]["new_initiatives"] += 1
        
        # Calculate average completion time
        completion_times = []
        for initiative in completed_in_period:
            if initiative["start_date"] and initiative["completion_date"]:
                start = datetime.fromisoformat(initiative["start_date"])
                end = datetime.fromisoformat(initiative["completion_date"])
                completion_times.append((end - start).total_seconds() / 3600)  # hours
        
        if completion_times:
            report["summary"]["avg_completion_time"] = sum(completion_times) / len(completion_times)
        
        # Get top improvement areas
        areas = tracker_data["improvement_areas"]
        if areas:
            sorted_areas = sorted(areas.items(), 
                                 key=lambda x: x[1]["total_initiatives"], 
                                 reverse=True)[:5]
            report["top_areas"] = [
                {
                    "area": area,
                    "total": data["total_initiatives"],
                    "completed": data["completed"],
                    "success_rate": data["success_rate"]
                }
                for area, data in sorted_areas
            ]
        
        # Generate recommendations
        if report["summary"]["completed_in_period"] < 3:
            report["recommendations"].append("Increase focus on completing initiatives")
        
        if report["summary"]["new_initiatives"] > 5:
            report["recommendations"].append("Consider consolidating similar initiatives")
        
        active_count = report["summary"]["active_initiatives"]
        if active_count > 10:
            report["recommendations"].append("Prioritize and focus on key initiatives")
        elif active_count < 3:
            report["recommendations"].append("Identify new improvement opportunities")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Improvement Tracker for Self-Improving Agents')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create new improvement initiative')
    create_parser.add_argument('--area', required=True, help='Improvement area')
    create_parser.add_argument('--description', required=True, help='Initiative description')
    create_parser.add_argument('--goals', required=True, help='Goals (comma-separated)')
    create_parser.add_argument('--priority', choices=['low', 'medium', 'high'], default='medium')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start an initiative')
    start_parser.add_argument('initiative_id', help='Initiative ID')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update initiative progress')
    update_parser.add_argument('initiative_id', help='Initiative ID')
    update_parser.add_argument('--progress', type=int, required=True, help='Progress percentage')
    update_parser.add_argument('--notes', help='Progress notes')
    
    # Complete command
    complete_parser = subparsers.add_parser('complete', help='Complete an initiative')
    complete_parser.add_argument('initiative_id', help='Initiative ID')
    complete_parser.add_argument('--success', action='store_true', help='Mark as successful')
    complete_parser.add_argument('--impact', type=int, default=0, help='Impact score (0-10)')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List initiatives')
    list_parser.add_argument('--status', help='Filter by status')
    list_parser.add_argument('--area', help='Filter by area')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get initiative details')
    get_parser.add_argument('initiative_id', help='Initiative ID')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate improvement report')
    report_parser.add_argument('--days', type=int, default=30, help='Report period in days')
    
    # Metrics command
    metrics_parser = subparsers.add_parser('metrics', help='Show improvement metrics')
    
    # Areas command
    areas_parser = subparsers.add_parser('areas', help='Show improvement areas')
    
    args = parser.parse_args()
    
    tracker = ImprovementTracker()
    
    if args.command == 'create':
        goals = args.goals.split(',')
        initiative_id = tracker.create_initiative(
            args.area, args.description, goals, args.priority
        )
        print(f"Created initiative: {initiative_id}")
    
    elif args.command == 'start':
        tracker.start_initiative(args.initiative_id)
    
    elif args.command == 'update':
        tracker.update_progress(args.initiative_id, args.progress, args.notes)
    
    elif args.command == 'complete':
        tracker.complete_initiative(args.initiative_id, args.success, args.impact)
    
    elif args.command == 'list':
        initiatives = tracker.list_initiatives(args.status, args.area)
        
        print("Improvement Initiatives:")
        print("=" * 80)
        
        for initiative in initiatives:
            status_icon = {
                "planned": "📋",
                "in_progress": "🚧",
                "completed_success": "✅",
                "completed_partial": "⚠️"
            }.get(initiative["status"], "❓")
            
            print(f"{status_icon} {initiative['id']}")
            print(f"  Area: {initiative['area']}")
            print(f"  Description: {initiative['description']}")
            print(f"  Status: {initiative['status']}")
            print(f"  Progress: {initiative['progress']}%")
            
            if initiative.get('start_date'):
                start = datetime.fromisoformat(initiative['start_date']).strftime('%Y-%m-%d')
                print(f"  Started: {start}")
            
            print()
    
    elif args.command == 'get':
        initiative = tracker.get_initiative(args.initiative_id)
        
        if initiative:
            print(f"Initiative: {initiative['id']}")
            print(f"Area: {initiative['area']}")
            print(f"Description: {initiative['description']}")
            print(f"Status: {initiative['status']}")
            print(f"Priority: {initiative['priority']}")
            print(f"Progress: {initiative['progress']}%")
            print()
            
            print("Goals:")
            for goal in initiative['goals']:
                print(f"  • {goal}")
            print()
            
            if initiative['notes']:
                print("Progress Notes:")
                for note in initiative['notes'][-5:]:  # Last 5 notes
                    date = datetime.fromisoformat(note['timestamp']).strftime('%Y-%m-%d %H:%M')
                    print(f"  [{date}] {note['progress']}%: {note['notes']}")
        else:
            print(f"Initiative {args.initiative_id} not found")
    
    elif args.command == 'report':
        report = tracker.generate_report(args.days)
        
        print(f"Improvement Report - {report['period']}")
        print("=" * 60)
        print(f"Generated: {report['generated']}")
        print()
        
        print("Summary:")
        print(f"- Active Initiatives: {report['summary']['active_initiatives']}")
        print(f"- Completed (Period): {report['summary']['completed_in_period']}")
        print(f"- New Initiatives: {report['summary']['new_initiatives']}")
        print(f"- Avg Completion Time: {report['summary']['avg_completion_time']:.1f} hours")
        print()
        
        if report['top_areas']:
            print("Top Improvement Areas:")
            for area in report['top_areas']:
                print(f"  • {area['area']}: {area['total']} total, {area['completed']} completed, {area['success_rate']:.1f}% success")
            print()
        
        if report['recommendations']:
            print("Recommendations:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
    
    elif args.command == 'metrics':
        metrics = tracker.get_metrics()
        
        print("Improvement Metrics")
        print("=" * 50)
        print(f"Total Initiatives: {metrics['total_initiatives']}")
        print(f"Completed Initiatives: {metrics['completed_initiatives']}")
        
        if metrics['total_initiatives'] > 0:
            success_rate = (metrics['completed_initiatives'] / metrics['total_initiatives']) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"Average Completion Time: {metrics['avg_completion_time']} hours")
    
    elif args.command == 'areas':
        areas = tracker.get_improvement_areas()
        
        print("Improvement Areas:")
        print("=" * 50)
        
        for area, data in areas.items():
            print(f"{area}:")
            print(f"  Total Initiatives: {data['total_initiatives']}")
            print(f"  Completed