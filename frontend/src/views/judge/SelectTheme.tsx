import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
    Button,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableRow,
} from '@material-ui/core';

import JudgeContestService from '../../services/JudgeContestService';
import { JuryContest } from '../../types/api';

const CustomButton = ({ navigate, ...rest }: { navigate: Function }) => {
    // Rendering element with the 'navigate' prop raises an error, so we have
    // to strip it: Warning: Invalid value for prop `navigate` on <a> tag.
    return React.createElement(Button, rest);
};

const SelectTheme: React.FC = () => {
    const [contests, setContests] = useState<JuryContest[]>([]);
    const { t } = useTranslation();

    useEffect(() => {
        const fetchContests = async (): Promise<void> => {
            const { data } = await JudgeContestService.getContests();
            setContests(data.results);
        };
        fetchContests();
    }, []);

    return (
        <TableContainer component={Paper}>
            <Table>
                <TableBody>
                    {contests.map((contest) => (
                        <React.Fragment key={contest.id}>
                            <TableRow>
                                <TableCell colSpan={4}>
                                    <b>{contest.title}</b>
                                </TableCell>
                            </TableRow>
                            {contest.themes.map((theme) => (
                                <TableRow key={theme.id}>
                                    <TableCell padding="checkbox" />
                                    <TableCell>{theme.title}</TableCell>
                                    <TableCell>
                                        {theme.ratings_number}/{theme.submissions_number}
                                    </TableCell>
                                    <TableCell align="right">
                                        <Link
                                            to={`/judge/contest/${contest.id}/theme/${theme.id}`}
                                            component={CustomButton}
                                            color="primary"
                                        >
                                            {t('open')}
                                        </Link>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </React.Fragment>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    );
};

export default SelectTheme;
