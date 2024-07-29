import acronyms from './syo-701-acronyms';
import Flashcard from './Flashcard';
import { useState } from 'react';
import { Container, Typography } from '@mui/material';

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
    <Container maxWidth="sm" sx={{padding: 4, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: '100%'}}>
      <div>
      <Typography variant='h3'>Security+ 701</Typography>
        <Typography variant='h3'>Acronym Flashcards</Typography>
      </div>
      <div>
        <Typography variant='body2'gutterBottom textAlign='end'>{currentCardIndex + 1} / {totalNumberOfCards}</Typography>  
        <Flashcard
          sx={{marginBottom: 4}} 
          acronym={shuffledCards[currentCardIndex]?.acronym} 
          fullform={shuffledCards[currentCardIndex]?.fullform} 
          definition={shuffledCards[currentCardIndex]?.definition} 
          next={() => setCurrentCardIndex(i => i+1)} 
        />
      </div>
    </Container>
  );
}

export default App;
