import React from 'react';

import { useTranslation } from 'react-i18next';

import { Link } from 'react-router-dom';

import {
    Button,
    Card,
    CardActions,
    CardContent,
    CardMedia,
    Grid,
    Typography,
} from '@material-ui/core';

import { Contest } from '../../store/contests/types';

interface ContestCardProps {
    contest: Contest;
}

const CustomButton = ({ navigate, ...rest }: { navigate: Function }) => {
    // Rendering element with the 'navigate' prop raises an error, so we have
    // to strip it: Warning: Invalid value for prop `navigate` on <a> tag.
    return React.createElement(Button, rest);
};

const ContestCard: React.FC<ContestCardProps> = (props) => {
    const { t } = useTranslation();

    const { contest } = props;

    return (
        <Card>
            <CardMedia
                component="img"
                image={contest.header_image || `${process.env.PUBLIC_URL}/img/no-photo.png`}
                width="100%"
                max-height="210"
                title="Contemplative Reptile"
            />
            <CardContent>
                <Typography gutterBottom variant="h5" component="h2">
                    {contest.title}
                </Typography>
                <Typography variant="body2" color="textSecondary" component="p">
                    {contest.description}
                </Typography>
            </CardContent>
            <CardActions>
                <Grid container alignItems="flex-start" justify="flex-end" direction="row">
                    <Link
                        to={`/contest/${contest.id}/upload`}
                        // to={`/contest/${contest.id}/details`}
                        component={CustomButton}
                        color="primary"
                    >
                        {t('open')}
                    </Link>
                </Grid>
            </CardActions>
        </Card>
    );
};

export default ContestCard;
