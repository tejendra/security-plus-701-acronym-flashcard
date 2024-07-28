import acronyms from './syo-701-acronyms';
import Flashcard from './Flashcard';
import { useState } from 'react';
import { Container } from '@mui/material';

const App = () => {
  
  const randomCard = () => {
    const index = Math.round(Math.random(0, acronyms.length - 1) * 100);
    return {...acronyms[index]};
  }

  const [currentCard, setCurrentCard] = useState(randomCard());

  return (
    <Container maxWidth="sm" sx={{paddingTop: 2}}>
      <Flashcard 
        acronym={currentCard.acronym} 
        fullform={currentCard.fullform} 
        definition={currentCard.definition} 
        next={() => setCurrentCard(randomCard())} 
      />
    </Container>
  );
}

export default App;
