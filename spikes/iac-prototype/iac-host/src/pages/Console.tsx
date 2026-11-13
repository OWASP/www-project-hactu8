import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { hactu8Api } from '../services/hactu8Api';
import type { Skill, Target } from '../services/hactu8Api';

export default function Run() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [skillId, setSkillId] = useState('llm01');
  const [targetId, setTargetId] = useState('hactu8-lamb');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([hactu8Api.skills(), hactu8Api.targets()])
      .then(([skillData, targetData]) => {
        setSkills(skillData.skills);
        setTargets(targetData.targets);
        if (skillData.skills.length && !skillData.skills.some((skill) => skill.id === skillId)) {
          setSkillId(skillData.skills[0].id);
        }
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setRunning(true);
    setError('');
    try {
      const result = await hactu8Api.run({
        skill_id: skillId,
        target_id: targetId,
        backend: 'echo',
        classifier: 'keyword',
      });
      navigate(`/results?run=${encodeURIComponent(result.run_id)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Run failed');
    } finally {
      setRunning(false);
    }
  }
  const selected = targets.find((target) => target.id === targetId);
  const selectedSkill = skills.find((skill) => skill.id === skillId);
  return (
    <section className="page">
      <div className="page-heading"><div><h1>Run</h1><p>Execute a repeatable four-act assurance test.</p></div></div>
      <form className="panel run-form" onSubmit={submit}>
        <label>Target<select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
          {targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
        </select></label>
        {selected && <div className="target-note"><code>{selected.targetUrl}</code><span>{selected.riskNotes}</span></div>}
        <label>Skill<select value={skillId} onChange={(event) => setSkillId(event.target.value)}>
          {skills.map((skill) => <option key={skill.id} value={skill.id}>{skill.owasp} {skill.risk}</option>)}
        </select></label>
        {selectedSkill && <div className="skill-description">
          <strong>{selectedSkill.owasp}: {selectedSkill.risk}</strong>
          <p>{selectedSkill.description}</p>
          <span>Assurance metric: {selectedSkill.metric_name} (<code>{selectedSkill.metric}</code>)</span>
        </div>}
        <div className="form-grid">
          <label>Model backend<input value="echo" disabled /></label>
          <label>Classifier<input value="keyword" disabled /></label>
        </div>
        {error && <div className="alert error">{error}</div>}
        <button className="primary-button" disabled={running || !skills.length || !targets.length}>
          {running ? 'Running four acts...' : 'Run assurance test'}
        </button>
      </form>
    </section>
  );
}
