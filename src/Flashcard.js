import React, { useEffect, useState } from 'react';
import { Button, Card, CardActions, CardContent, Typography } from "@mui/material";

const Flashcard = ({acronym, fullform, definition, next}) => {
  const [show, setShow] = useState(false);

  useEffect(() => {
    setShow(false);
  }, [acronym]);

  return (
    <Card elevation={3}>
      <CardContent>
        <Typography variant='h3' gutterBottom textAlign='center' color='primary'>{acronym}</Typography>
        {show && (
          <>
            <Typography variant='h5' color="text.secondary" gutterBottom textAlign='center'>{fullform}</Typography>
            <Typography variant='body'>{definition}</Typography>
          </>
        )}
      </CardContent>
      <CardActions>
        <Button size="small" onClick={() => setShow(show => !show)}>{show ? 'Hide' : 'Show'}</Button>
        <Button size="small" onClick={() => next()}>Next</Button>
      </CardActions>
    </Card>
  )
}

export default Flashcard;