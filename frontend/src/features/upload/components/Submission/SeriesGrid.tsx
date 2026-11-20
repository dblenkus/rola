import React, { ReactNode } from 'react';

interface SeriesGridProps {
  titleField: ReactNode;
  descriptionField: ReactNode;
}

// A series' one title and description, under its photographs.
const SeriesGrid: React.FC<SeriesGridProps> = (props) => {
  const { titleField, descriptionField } = props;

  return (
    <div className="upload-series">
      {titleField}
      {descriptionField}
    </div>
  );
};

export default SeriesGrid;
