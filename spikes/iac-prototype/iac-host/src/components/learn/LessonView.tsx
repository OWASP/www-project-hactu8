import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeSanitize from 'rehype-sanitize';
import { hactu8Api } from '../../services/hactu8Api';
import type { Lesson } from '../../services/hactu8Api';

// Lessons link to files inside the lab folder (../README.md, assets/...). Those
// paths mean nothing in the console, so they render as code, not as links.
function LessonLink({ href, children }: { href?: string; children?: React.ReactNode }) {
  if (href && /^https?:\/\//.test(href)) {
    return <a href={href} target="_blank" rel="noreferrer">{children}</a>;
  }
  return <span className="lesson-file" title={href}>{children}</span>;
}

export default function LessonView({ skillId }: { skillId: string }) {
  const [lesson, setLesson] = useState<Lesson | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let live = true;
    setLesson(null);
    setError('');
    hactu8Api.lesson(skillId)
      .then((value) => { if (live) setLesson(value); })
      .catch((err: Error) => { if (live) setError(err.message); });
    return () => { live = false; };
  }, [skillId]);

  if (error) return <div className="panel empty-state"><h2>No lesson</h2><p>{error}</p></div>;
  if (!lesson) return <div className="panel empty-state"><p>Loading lesson...</p></div>;
  return (
    <article className="panel lesson">
      <h2>{lesson.title || `${lesson.owasp} ${lesson.risk}`}</h2>
      {Object.entries(lesson.sections).map(([title, text]) => (
        <section key={title} className="lesson-section">
          <h3>{title}</h3>
          <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}
            components={{ a: LessonLink }}>{text}</ReactMarkdown>
        </section>
      ))}
    </article>
  );
}
