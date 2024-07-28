import acronyms from './syo-701-acronyms';
import Flashcard from './Flashcard';
import { useState } from 'react';
import { Box } from '@mui/material';

const App = () => {
  
  const randomCard = () => {
    const index = Math.round(Math.random(0, acronyms.length - 1) * 100);
    return {...acronyms[index]};
  }

  const [currentCard, setCurrentCard] = useState(randomCard());

  return (
    <Box sx={{width: 500, height: '100%', marginX: 'auto', padding: 3, backgroundColor: ''}}>
      <Flashcard 
        acronym={currentCard.acronym} 
        fullform={currentCard.fullform} 
        definition={currentCard.definition} 
        next={() => setCurrentCard(randomCard())} 
      />
    </Box>
  );
}

export default App;
