import acronyms from './syo-701-acronyms';
import Flashcard from './Flashcard';
import { useState } from 'react';
import { Container } from '@mui/material';

const App = () => {
  const randomCard = () => {
    const index = Math.floor(Math.random() * acronyms.length - 1);
    return acronyms[index];
  }

  const [currentCard, setCurrentCard] = useState(randomCard());

  const nextCard = () => {
    setCurrentCard(randomCard());
  }
  
  return (
    <Container maxWidth="sm" sx={{paddingTop: 2}}>
      <Flashcard 
        acronym={currentCard?.acronym} 
        fullform={currentCard?.fullform} 
        definition={currentCard?.definition} 
        next={() => nextCard()} 
      />
    </Container>
  );
}

export default App;
