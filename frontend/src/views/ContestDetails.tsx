import React from 'react';
import { useParams } from 'react-router';

import { Typography } from '@mui/material';

import ContestService from '../services/ContestService';
import { Contest } from '../types/api';

import HeaderImage from '../components/Layout/HeaderImage';
import NoticeHtml from '../components/Upload/NoticeHtml';
import UploadButton from '../components/Upload/UploadButton';

interface RouteMatchParams {
  contestId: string;
}

interface ContestDetailsProps {
  match: { params: RouteMatchParams };
}

interface ContestDetailsState {
  contest: Contest | null;
}

class ContestDetails extends React.Component<
  ContestDetailsProps,
  ContestDetailsState
> {
  state = {
    contest: null,
  };

  async componentDidMount() {
    const { contestId } = this.props.match.params;
    const { data: contest } = await ContestService.getContest(contestId);
    this.setState({ contest });
  }

  render(): React.ReactNode {
    const { contest } = this.state;

    if (contest === null) return null;

    const {
      header_image: headerImage,
      notice_html: noticeHtml,
      title,
      id: contestId,
    } = contest as unknown as Contest;

    return (
      <>
        {headerImage ? (
          <HeaderImage src={headerImage} />
        ) : (
          <Typography align="center" variant="h2">
            {title}
          </Typography>
        )}
        <UploadButton contestId={contestId} />
        <NoticeHtml notice={noticeHtml ?? ''} />
        <UploadButton contestId={contestId} />
      </>
    );
  }
}

export default function RouteView() {
  const params = useParams();
  const contestId = params.contestId;
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  return <ContestDetails match={{ params: { contestId } }} />;
}
