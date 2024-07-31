import React, { useEffect, useState } from 'react';
import { Button, Card, CardActions, CardContent, CardHeader, Typography } from "@mui/material";

const Flashcard = ({acronym, fullform, definition, category, next, sx}) => {
  const [show, setShow] = useState(false);

  useEffect(() => {
    setShow(false);
  }, [acronym]);

  return (
    <Card elevation={5} sx={{borderRadius: 4, backgroundColor: '#F8F1F6', ...sx}}>
      <CardHeader 
        sx={{ 
          borderRadius: 4, 
          backgroundColor: '#505DEE', 
          color: theme => theme.palette.getContrastText('#505DEE'),
          minHeight: '100px',
        }} 
        title={acronym}
        titleTypographyProps={{display:'flex', justifyContent: 'center', fontSize: '3rem'}}
        subheader={category} 
        subheaderTypographyProps={{display:'flex', justifyContent: 'center', color:"inherit"}}/>
      
      
      {show && (
        <CardContent>
          <Typography variant='h5' color="text.primary" gutterBottom textAlign='center'>{fullform}</Typography>
          <Typography variant='body1' color='text.secondary' textAlign='center'>{definition}</Typography>
        </CardContent>
      )}
     
      <CardActions sx={{justifyContent: 'flex-end'}}>
        <Button size="small" onClick={() => setShow(show => !show)}>{show ? 'Hide' : 'Show'}</Button>
        <Button size="small" onClick={() => next()}>Next</Button>
      </CardActions>
    </Card>
  )
}

export default Flashcard;
