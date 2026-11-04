import React from 'react';
import DOMPurify from 'dompurify';

// A separate instance keeps the hook below out of other DOMPurify users.
const purify = DOMPurify(window);

// Notices may open links in a new tab, which must not get the opener.
purify.addHook('afterSanitizeAttributes', (node) => {
  if (node instanceof Element && node.hasAttribute('target')) {
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

interface NoticeHtmlProps {
  notice: string;
}

const NoticeHtml: React.FC<NoticeHtmlProps> = ({ notice }) => {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: purify.sanitize(notice, { ADD_ATTR: ['target'] }),
      }}
    />
  );
};

export default NoticeHtml;
