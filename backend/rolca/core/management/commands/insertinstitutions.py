"""Import participating institutions from a CSV file."""

import os

from django.core.management.base import BaseCommand, CommandError

from rolca.core.models import Institution


class Command(BaseCommand):
    """Add list of institutions to the database."""

    help = 'Add list of institutions to the database.'

    def add_arguments(self, parser):
        """Accept the institutions CSV filename."""
        parser.add_argument(
            'file_names', nargs='+', default=False, help='List of files to import.'
        )

    def handle(self, *args, **options):
        """Import institutions from the supplied file."""
        for file_name in options['file_names']:
            if not os.path.isfile(file_name):
                raise CommandError('{} does not exists.'.format(file_name))

        institutions = []
        for file_name in options['file_names']:
            with open(file_name) as in_file:
                for line in in_file.readlines():
                    line = line.rstrip()
                    if line == "":
                        continue

                    institutions.append(Institution(name=line, kind=Institution.SCHOOL))

        Institution.objects.bulk_create(institutions, ignore_conflicts=True)

        self.stdout.write("Done.")
