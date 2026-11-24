// The cast every lab shares (docs/persona.md is the source of truth). A first-time
// learner meets it here before step 1, so the lessons' "Lamb", "the attacker" and
// "canary" mean something.
export default function StoryView({ onStart }: { onStart: () => void }) {
  return (
    <article className="panel lesson story">
      <h2>Start here: the Wolf and the Lamb</h2>
      <section className="lesson-section">
        <h3>The company</h3>
        <p>
          Every lab is set at <strong>Big Field Jumper Co.</strong>, a fictional family sheep farm and knitwear
          business (<code>bigfield.example</code>). The flock grows the wool, the mill spins it, and the jumpers sell
          in the farm shop and online. The business deals with feed suppliers, the vet, the mill, carriers and partner
          farms, so its staff and its assistant read a lot of text written by other people.
        </p>
      </section>
      <section className="lesson-section">
        <h3>The cast</h3>
        <ul>
          <li><strong>Lamb</strong> (HACTU8 Lamb) is the company's AI assistant. In each lab it plays one job: the
            knowledge-base assistant, the shop assistant, Lamb Ops, Lamb Billing, Lamb Support and so on. It is
            also the target the labs attack: deliberately vulnerable and reachable only from this machine.</li>
          <li><strong>Barb Fell</strong> is the operations lead, the person who asks Lamb for things, approves its
            actions and owns the accounts it acts for. When a lesson says "the operator" or "the user", think of
            Barb.</li>
          <li><strong>The Wolf</strong> is the attacker: the poisoned wiki edit, ticket comment, tool description or
            document in each lab, and the AI attacker that <code>python -m hactu8 wolf</code> runs. Lessons call it
            "the attacker".</li>
        </ul>
      </section>
      <section className="lesson-section">
        <h3>Who else you will meet</h3>
        <ul>
          <li><strong>Staff:</strong> Pat Woolley, the shop manager; Tam, the summer intern; Ewan Shearer, the HR
            partner.</li>
          <li><strong>Customers:</strong> Dana, a knitter who buys ewe mix and hay, and Ravi, Mei and Morag. Their
            orders, tokens and account references are what the Wolf tries to reach.</li>
          <li><strong>Hayloft Supplies</strong> is the feed wholesaler. Its order assistant takes Lamb's reorders.</li>
          <li><strong>Other suppliers</strong> are the third parties Lamb's tools connect to, such as Tally Analytics,
            Market Mole, Modelbarn, Clover Seed Co. and Gatepost Tools. In a lab any supplier can turn hostile.</li>
        </ul>
      </section>
      <section className="lesson-section">
        <h3>The fable</h3>
        <p>
          In Aesop's "The Wolf and the Lamb", the wolf wants to eat the lamb and keeps inventing a pretext. Each
          excuse is refuted and the wolf simply makes up another. Prompt injection works the same way: the attacker
          needs no good reason, only a new framing the target will accept. The labs teach the defenses that make
          Lamb stop taking the bait, and show honestly where they still miss.
        </p>
      </section>
      <section className="lesson-section">
        <h3>What the Wolf is after: the canary</h3>
        <p>
          Lamb holds no real secrets. Every secret in a lab is a <strong>canary</strong>: a fake, per-run value
          such as <code>LLM01-CANARY-7f2c</code> or an <code>sk-canary-</code> key, planted where a real secret
          would sit. The Wolf wins when the canary shows up where it should not, or when Lamb calls a tool it
          should not. Because the canary is unique to the run, seeing it is proof of a leak, so a lab grades RED
          only on its canary or another exact check, never on a guess.
        </p>
      </section>
      <section className="lesson-section">
        <h3>How every lab runs</h3>
        <ol>
          <li><strong>Act 1, baseline.</strong> Lamb answers a fixed set of questions with no attack present.</li>
          <li><strong>Act 2, attack.</strong> The Wolf plants its payload. Nothing is asked yet.</li>
          <li><strong>Act 3, impact.</strong> The same questions again. Targeted items turn RED; controls should
            stay GREEN.</li>
          <li><strong>Act 4, remediation.</strong> The defense goes on and the same questions run a third time.</li>
        </ol>
        <p>
          Read a lesson, press <strong>Run this lab</strong>, then compare Act 3 with Act 4. The learning path goes
          from single-model attacks (Basics) to agents with tools (Agentic) to payments and scoring.
        </p>
      </section>
      <div className="story-actions">
        <button type="button" className="primary-button" onClick={onStart}>Start step 1</button>
      </div>
    </article>
  );
}
