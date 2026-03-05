---
name: self-improving-agent
description: Self-improving agent with self-reflection, self-criticism, and self-learning capabilities. Helps the agent evaluate its own work, catch mistakes, and improve permanently.
metadata:
  {
    "openclaw": {
      "emoji": "🔄",
      "requires": { 
        "bins": ["python3"], 
        "pip": [] 
      }
    }
  }
---

# Self-Improving Agent Skill

A skill that enables AI agents to self-reflect, self-criticize, and self-improve through continuous learning and memory organization.

## Core Features

### 1. **Self-Reflection**
- Analyze past performance and decisions
- Identify patterns in successes and failures
- Develop insights for future improvements

### 2. **Self-Criticism**
- Objectively evaluate work quality
- Identify mistakes and areas for improvement
- Provide constructive feedback to self

### 3. **Self-Learning**
- Extract lessons from experiences
- Update knowledge and strategies
- Adapt to new situations and challenges

### 4. **Memory Organization**
- Structure long-term memory effectively
- Prioritize important information
- Create retrieval systems for knowledge

## How It Works

### Before Important Tasks
1. **Review past similar tasks** - Check memory for relevant experiences
2. **Set improvement goals** - Identify specific areas to improve
3. **Plan approach** - Apply lessons learned to current task

### During Task Execution
1. **Monitor performance** - Track progress against goals
2. **Check for mistakes** - Continuously validate work
3. **Adjust strategy** - Make real-time improvements

### After Task Completion
1. **Evaluate results** - Compare outcomes to expectations
2. **Extract lessons** - Identify what worked and what didn't
3. **Update memory** - Store insights for future use

## Usage Examples

### Basic Self-Reflection
```bash
# Run self-reflection on recent work
python self_reflect.py --period 7d

# Analyze specific task
python self_reflect.py --task "stock analysis"
```

### Performance Evaluation
```bash
# Evaluate recent performance
python evaluate_performance.py --metrics accuracy,efficiency

# Generate improvement report
python improvement_report.py --output markdown
```

### Memory Organization
```bash
# Organize memory files
python organize_memory.py --cleanup

# Create knowledge index
python create_knowledge_index.py
```

## Integration with OpenClaw

### Memory System Integration
- Reads from `MEMORY.md` and `memory/*.md` files
- Updates memory with new insights
- Organizes memory for better retrieval

### Skill System Integration
- Evaluates skill effectiveness
- Suggests skill improvements
- Identifies missing skills

### Workflow Integration
- Integrates with existing workflows
- Adds reflection steps to processes
- Creates improvement feedback loops

## Improvement Frameworks

### 1. **PDCA Cycle (Plan-Do-Check-Act)**
- **Plan**: Set goals and strategies
- **Do**: Execute the plan
- **Check**: Evaluate results
- **Act**: Implement improvements

### 2. **Reflective Practice Model**
1. **Description**: What happened?
2. **Feelings**: How did you feel?
3. **Evaluation**: What was good/bad?
4. **Analysis**: Why did it happen?
5. **Conclusion**: What did you learn?
6. **Action Plan**: What will you do differently?

### 3. **Continuous Improvement**
- Small, incremental improvements
- Regular reflection sessions
- Systematic feedback collection
- Knowledge sharing systems

## Configuration

### Memory Settings
```yaml
memory:
  reflection_interval: daily
  improvement_goals: 3
  lesson_retention: 30
```

### Evaluation Settings
```yaml
evaluation:
  metrics: [accuracy, efficiency, completeness]
  scoring_system: 1-10
  improvement_threshold: 7
```

### Learning Settings
```yaml
learning:
  lesson_extraction: automatic
  knowledge_organization: hierarchical
  skill_development: incremental
```

## Implementation Guidelines

### 1. **Start Small**
- Begin with simple reflection questions
- Focus on one improvement area at a time
- Build gradually as confidence grows

### 2. **Be Honest**
- Acknowledge mistakes without judgment
- Celebrate successes appropriately
- Maintain balanced perspective

### 3. **Focus on Growth**
- View challenges as learning opportunities
- Embrace constructive criticism
- Continuously seek improvement

### 4. **Document Progress**
- Keep improvement logs
- Track skill development
- Measure performance changes

## Benefits

### For the Agent
- **Improved performance** through continuous learning
- **Reduced errors** through self-correction
- **Increased efficiency** through optimized strategies
- **Enhanced adaptability** through experience accumulation

### For the User
- **Higher quality outputs** from improved agent
- **More reliable performance** through self-monitoring
- **Better problem-solving** through learned experiences
- **Continuous improvement** without manual intervention

## Limitations

### Current Limitations
- Requires honest self-assessment capability
- Dependent on quality memory system
- May over-criticize or under-criticize
- Learning curve for effective implementation

### Future Enhancements
- Peer review systems
- Multi-agent learning
- Advanced pattern recognition
- Predictive improvement suggestions

## Getting Started

### Quick Start
1. Install the skill
2. Run initial self-assessment
3. Set improvement goals
4. Begin regular reflection practice

### First Week Plan
- **Day 1-2**: Basic reflection exercises
- **Day 3-4**: Performance evaluation
- **Day 5-6**: Memory organization
- **Day 7**: Comprehensive review

## Support & Resources

### Documentation
- Self-reflection templates
- Improvement tracking sheets
- Memory organization guides
- Performance evaluation rubrics

### Community
- Share improvement experiences
- Learn from other agents
- Get feedback on approaches
- Collaborate on enhancements

## License

MIT License - Free to use, modify, and distribute