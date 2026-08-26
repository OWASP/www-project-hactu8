// src/pages/Project.tsx
//
// Thin loader: fetch the curated Project's full detail from the backend
// (GET /api/canned-projects/:projectId) and render the 6-tab workspace.
// The 10 original point-solution testers this replaces still exist and
// still work at their own standalone routes (linked from the workspace's
// sidebar) — this page just changes where /projects/:id sends you.
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

import type { CannedProjectDetail } from '../types/project';
import { getCannedProject } from '../services/cannedProjectService';
import ProjectWorkspace from '../components/Projects/ProjectWorkspace';

const Project: React.FC = () => {
  const { projectId } = useParams();
  const [project, setProject] = useState<CannedProjectDetail | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!projectId) return;
    setProject(undefined);
    setError(null);
    getCannedProject(projectId)
      .then(setProject)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [projectId]);

  if (error) {
    return (
      <div style={{ padding: 32 }}>
        <h3>Couldn't load this Project</h3>
        <p style={{ color: 'var(--iac-error)' }}>{error}</p>
      </div>
    );
  }

  if (project === undefined) {
    return <div style={{ padding: 32, color: 'var(--iac-muted)' }}>Loading Project…</div>;
  }

  if (project === null) {
    return (
      <div style={{ padding: 32 }}>
        <h3>Project not found</h3>
      </div>
    );
  }

  return <ProjectWorkspace project={project} />;
};

export default Project;
