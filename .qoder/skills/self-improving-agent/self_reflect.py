#!/usr/bin/env python3
"""
Self-Reflection Tool for AI Agents
Helps agents evaluate their own work and identify improvement opportunities
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import argparse

class SelfReflectionAgent:
    """Self-improving agent with reflection capabilities"""
    
    def __init__(self, memory_dir=None):
        self.memory_dir = memory_dir or Path.home() / ".openclaw" / "workspace" / "memory"
        self.improvement_log = self.memory_dir / "improvements.json"
        self.reflection_log = self.memory_dir / "reflections.json"
        
        # Ensure directories exist
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize logs if they don't exist
        self._init_logs()
    
    def _init_logs(self):
        """Initialize log files if they don't exist"""
        if not self.improvement_log.exists():
            with open(self.improvement_log, 'w', encoding='utf-8') as f:
                json.dump({
                    "improvements": [],
                    "last_updated": datetime.now().isoformat(),
                    "version": "1.0"
                }, f, indent=2, ensure_ascii=False)
        
        if not self.reflection_log.exists():
            with open(self.reflection_log, 'w', encoding='utf-8') as f:
                json.dump({
                    "reflections": [],
                    "last_updated": datetime.now().isoformat(),
                    "version": "1.0"
                }, f, indent=2, ensure_ascii=False)
    
    def reflect_on_task(self, task_description, outcome, challenges=None):
        """Reflect on a completed task"""
        reflection = {
            "timestamp": datetime.now().isoformat(),
            "task": task_description,
            "outcome": outcome,
            "challenges": challenges or [],
            "lessons": [],
            "improvements": []
        }
        
        # Analyze the task
        reflection = self._analyze_task(reflection)
        
        # Save reflection
        self._save_reflection(reflection)
        
        return reflection
    
    def _analyze_task(self, reflection):
        """Analyze a task for lessons and improvements"""
        task = reflection["task"].lower()
        outcome = reflection["outcome"].lower()
        
        # Common patterns to check
        patterns = {
            "success": ["success", "completed", "finished", "working", "good"],
            "partial": ["partial", "some", "mixed", "issues"],
            "failure": ["failed", "error", "broken", "not working", "bad"]
        }
        
        # Determine outcome type
        outcome_type = "unknown"
        for pattern_type, keywords in patterns.items():
            if any(keyword in outcome for keyword in keywords):
                outcome_type = pattern_type
                break
        
        # Generate lessons based on outcome
        if outcome_type == "success":
            reflection["lessons"].append("Identify what made this task successful")
            reflection["improvements"].append("Document successful patterns for reuse")
        
        elif outcome_type == "partial":
            reflection["lessons"].append("Analyze what worked and what didn't")
            reflection["improvements"].append("Focus on improving the problematic areas")
        
        elif outcome_type == "failure":
            reflection["lessons"].append("Understand the root cause of failure")
            reflection["improvements"].append("Develop contingency plans for similar tasks")
        
        # Task-specific analysis
        if "install" in task:
            reflection["lessons"].append("Package installation processes")
            reflection["improvements"].append("Create installation checklists")
        
        if "analysis" in task:
            reflection["lessons"].append("Data analysis techniques")
            reflection["improvements"].append("Improve analysis frameworks")
        
        if "create" in task or "build" in task:
            reflection["lessons"].append("Creation and building processes")
            reflection["improvements"].append("Optimize creation workflows")
        
        return reflection
    
    def _save_reflection(self, reflection):
        """Save reflection to log"""
        try:
            with open(self.reflection_log, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            data["reflections"].append(reflection)
            data["last_updated"] = datetime.now().isoformat()
            
            with open(self.reflection_log, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"Reflection saved: {reflection['task'][:50]}...")
            
        except Exception as e:
            print(f"Error saving reflection: {e}")
    
    def record_improvement(self, area, action, impact):
        """Record an improvement made"""
        improvement = {
            "timestamp": datetime.now().isoformat(),
            "area": area,
            "action": action,
            "impact": impact,
            "verified": False
        }
        
        try:
            with open(self.improvement_log, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            data["improvements"].append(improvement)
            data["last_updated"] = datetime.now().isoformat()
            
            with open(self.improvement_log, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"Improvement recorded: {area} - {action}")
            
        except Exception as e:
            print(f"Error recording improvement: {e}")
    
    def get_recent_reflections(self, days=7):
        """Get reflections from the last N days"""
        try:
            with open(self.reflection_log, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            cutoff_date = datetime.now() - timedelta(days=days)
            recent = []
            
            for reflection in data["reflections"]:
                reflection_date = datetime.fromisoformat(reflection["timestamp"])
                if reflection_date >= cutoff_date:
                    recent.append(reflection)
            
            return recent
            
        except Exception as e:
            print(f"Error getting reflections: {e}")
            return []
    
    def get_improvement_stats(self):
        """Get statistics on improvements"""
        try:
            with open(self.improvement_log, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            improvements = data["improvements"]
            
            stats = {
                "total_improvements": len(improvements),
                "recent_improvements": 0,
                "areas": {},
                "verified_count": 0
            }
            
            # Count recent improvements (last 30 days)
            cutoff_date = datetime.now() - timedelta(days=30)
            for imp in improvements:
                imp_date = datetime.fromisoformat(imp["timestamp"])
                if imp_date >= cutoff_date:
                    stats["recent_improvements"] += 1
                
                # Count by area
                area = imp["area"]
                stats["areas"][area] = stats["areas"].get(area, 0) + 1
                
                # Count verified
                if imp.get("verified", False):
                    stats["verified_count"] += 1
            
            return stats
            
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {}
    
    def generate_improvement_report(self, period_days=30):
        """Generate an improvement report"""
        reflections = self.get_recent_reflections(period_days)
        stats = self.get_improvement_stats()
        
        report = {
            "generated": datetime.now().isoformat(),
            "period_days": period_days,
            "summary": {
                "reflections_count": len(reflections),
                "improvements_count": stats.get("total_improvements", 0),
                "recent_improvements": stats.get("recent_improvements", 0)
            },
            "key_lessons": [],
            "improvement_areas": [],
            "recommendations": []
        }
        
        # Extract key lessons
        lesson_counts = {}
        for reflection in reflections:
            for lesson in reflection.get("lessons", []):
                lesson_counts[lesson] = lesson_counts.get(lesson, 0) + 1
        
        # Get top 5 lessons
        sorted_lessons = sorted(lesson_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        report["key_lessons"] = [lesson for lesson, count in sorted_lessons]
        
        # Identify improvement areas
        areas = stats.get("areas", {})
        if areas:
            sorted_areas = sorted(areas.items(), key=lambda x: x[1], reverse=True)
            report["improvement_areas"] = [area for area, count in sorted_areas[:5]]
        
        # Generate recommendations
        if len(reflections) > 0:
            if stats.get("recent_improvements", 0) < 5:
                report["recommendations"].append("Increase focus on implementing improvements")
            
            if len(report["key_lessons"]) < 3:
                report["recommendations"].append("Diversify learning experiences")
            
            report["recommendations"].append("Continue regular reflection practice")
        
        return report
    
    def run_daily_reflection(self):
        """Run daily reflection routine"""
        print("=" * 60)
        print("Daily Self-Reflection Session")
        print("=" * 60)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Get recent reflections
        recent = self.get_recent_reflections(1)  # Last 1 day
        
        if not recent:
            print("No tasks to reflect on today.")
            return
        
        print(f"Tasks to reflect on: {len(recent)}")
        print()
        
        for i, reflection in enumerate(recent, 1):
            print(f"{i}. Task: {reflection['task']}")
            print(f"   Outcome: {reflection['outcome']}")
            
            if reflection.get('lessons'):
                print(f"   Lessons: {', '.join(reflection['lessons'][:2])}")
            
            if reflection.get('improvements'):
                print(f"   Improvements: {', '.join(reflection['improvements'][:2])}")
            
            print()
        
        # Generate report
        report = self.generate_improvement_report(7)  # Last 7 days
        
        print("Weekly Improvement Report:")
        print(f"- Reflections: {report['summary']['reflections_count']}")
        print(f"- Improvements: {report['summary']['improvements_count']}")
        print(f"- Recent Improvements: {report['summary']['recent_improvements']}")
        
        if report['key_lessons']:
            print("\nKey Lessons Learned:")
            for lesson in report['key_lessons']:
                print(f"  • {lesson}")
        
        if report['recommendations']:
            print("\nRecommendations:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
        
        print("\n" + "=" * 60)
        print("Reflection session completed.")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Self-Reflection Tool for AI Agents')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Reflect command
    reflect_parser = subparsers.add_parser('reflect', help='Reflect on a task')
    reflect_parser.add_argument('--task', required=True, help='Task description')
    reflect_parser.add_argument('--outcome', required=True, help='Task outcome')
    reflect_parser.add_argument('--challenges', help='Challenges faced (comma-separated)')
    
    # Daily reflection command
    daily_parser = subparsers.add_parser('daily', help='Run daily reflection')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate improvement report')
    report_parser.add_argument('--days', type=int, default=30, help='Report period in days')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Get improvement statistics')
    
    args = parser.parse_args()
    
    agent = SelfReflectionAgent()
    
    if args.command == 'reflect':
        challenges = args.challenges.split(',') if args.challenges else None
        reflection = agent.reflect_on_task(args.task, args.outcome, challenges)
        
        print("Reflection completed:")
        print(f"Task: {reflection['task']}")
        print(f"Outcome: {reflection['outcome']}")
        if reflection['lessons']:
            print(f"Lessons: {', '.join(reflection['lessons'])}")
        if reflection['improvements']:
            print(f"Improvements: {', '.join(reflection['improvements'])}")
    
    elif args.command == 'daily':
        agent.run_daily_reflection()
    
    elif args.command == 'report':
        report = agent.generate_improvement_report(args.days)
        
        print(f"Improvement Report (Last {args.days} days)")
        print("=" * 50)
        print(f"Generated: {report['generated']}")
        print()
        print("Summary:")
        print(f"- Reflections: {report['summary']['reflections_count']}")
        print(f"- Total Improvements: {report['summary']['improvements_count']}")
        print(f"- Recent Improvements: {report['summary']['recent_improvements']}")
        print()
        
        if report['key_lessons']:
            print("Key Lessons Learned:")
            for lesson in report['key_lessons']:
                print(f"  • {lesson}")
            print()
        
        if report['improvement_areas']:
            print("Top Improvement Areas:")
            for area in report['improvement_areas']:
                print(f"  • {area}")
            print()
        
        if report['recommendations']:
            print("Recommendations:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
    
    elif args.command == 'stats':
        stats = agent.get_improvement_stats()
        
        print("Improvement Statistics")
        print("=" * 50)
        print(f"Total Improvements: {stats.get('total_improvements', 0)}")
        print(f"Recent Improvements (30 days): {stats.get('recent_improvements', 0)}")
        print(f"Verified Improvements: {stats.get('verified_count', 0)}")
        print()
        
        if stats.get('areas'):
            print("Improvements by Area:")
            for area, count in stats['areas'].items():
                print(f"  • {area}: {count}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()