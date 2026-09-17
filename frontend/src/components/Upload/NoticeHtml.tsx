import React from 'react';

interface NoticeHtmlProps {
    notice: string;
}

const NoticeHtml: React.FC<NoticeHtmlProps> = ({ notice }) => {
    return <div dangerouslySetInnerHTML={{ __html: notice }} />;
};

export default NoticeHtml;
