import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router-dom';

import {
    Button,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableRow,
} from '@material-ui/core';

import ContestService from '../../services/ContestService';
import { Contest } from '../../types/api';
import LoadingProgress from '../../components/LoadingProgress';

interface RouteMatchParams {
    contestId: string;
}
const CustomButton = ({ navigate, ...rest }: { navigate: Function }) => {
    // Rendering element with the 'navigate' prop raises an error, so we have
    // to strip it: Warning: Invalid value for prop `navigate` on <a> tag.
    return React.createElement(Button, rest);
};

const SelectTheme: React.FC = () => {
    const [contest, setContest] = useState<null | Contest>(null);
    const { contestId } = useParams<RouteMatchParams>();
    const { t } = useTranslation();

    useEffect(() => {
        const fetchContest = async (): Promise<void> => {
            const { data } = await ContestService.getContest(contestId);
            setContest(data);
        };
        fetchContest();
    }, [contestId]);

    if (!contest) return <LoadingProgress />;

    return (
        <TableContainer component={Paper}>
            <Table>
                <TableBody>
                    <TableRow>
                        <TableCell colSpan={3}>
                            <b>{contest.title}</b>
                        </TableCell>
                    </TableRow>
                    {contest.themes.map((theme) => (
                        <TableRow key={theme.id}>
                            <TableCell padding="checkbox" />
                            <TableCell>{theme.title}</TableCell>
                            <TableCell align="right">
                                <Link
                                    to={`/results/contest/${contest.id}/theme/${theme.id}`}
                                    component={CustomButton}
                                    color="primary"
                                >
                                    {t('view')}
                                </Link>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    );
};

export default SelectTheme;
