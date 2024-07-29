import acronyms from './syo-701-acronyms';
import Flashcard from './Flashcard';
import { useState } from 'react';
import { Box, Container, Typography } from '@mui/material';

const App = () => {
  const shuffle = (array) => { 
    for (let i = array.length - 1; i > 0; i--) { 
      const j = Math.floor(Math.random() * (i + 1)); 
      [array[i], array[j]] = [array[j], array[i]]; 
    } 
    return array; 
  }

  const shuffledCards = shuffle(acronyms);
  const totalNumberOfCards = shuffledCards.length;
  const [currentCardIndex, setCurrentCardIndex] = useState(0);
  
  return (
    <Container maxWidth="sm" sx={{padding: 4}}>
      <Box sx={{marginBottom: 5}}>
        <Typography variant='h3'>Security+ 701</Typography>
        <Typography variant='h3'>Acronym Flashcards</Typography>
      </Box>
      <Box>
        <Typography variant='body2' gutterBottom textAlign='end'>{currentCardIndex + 1} / {totalNumberOfCards}</Typography>  
        <Flashcard
          acronym={shuffledCards[currentCardIndex]?.acronym} 
          fullform={shuffledCards[currentCardIndex]?.fullform} 
          definition={shuffledCards[currentCardIndex]?.definition} 
          next={() => setCurrentCardIndex(i => i+1)} 
        />
      </Box>
    </Container>
  );
}

export default App;
