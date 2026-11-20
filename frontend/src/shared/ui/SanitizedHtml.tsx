import DOMPurify from 'dompurify';

// A separate instance keeps the hook below out of other DOMPurify users.
const purify = DOMPurify(window);

// The content may open links in a new tab, which must not get the opener.
purify.addHook('afterSanitizeAttributes', (node) => {
  if (node instanceof Element && node.hasAttribute('target')) {
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

// Shows HTML that the server supplies, such as a contest's notice, without
// anything in it that could run script, in the prose styles of app.css.
export default function SanitizedHtml({ html }: { html: string }) {
  return (
    <div
      className="ui-prose"
      dangerouslySetInnerHTML={{
        __html: purify.sanitize(html, { ADD_ATTR: ['target'] }),
      }}
    />
  );
}
