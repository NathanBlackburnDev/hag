// https://stackoverflow.com/questions/57042145/add-bullets-to-each-new-line-within-a-textarea/57042927#57042927
// Add a bullet point to each new line automatically
const bullet = "\u2022";
const bulletWithSpace = `${bullet} `;
const enter = 13;


const handleInput = (event) => {
  const { keyCode, target } = event;
  const { selectionStart, value } = target;
  
  if (keyCode === enter) {
    console.log('a');
    target.value = [...value]
      .map((c, i) => i === selectionStart - 1
        ? `\n${bulletWithSpace}`
        : c
      )
      .join('');
      console.log(target.value);
      
    target.selectionStart = selectionStart+bulletWithSpace.length;
    target.selectionEnd = selectionStart+bulletWithSpace.length;
  }
  
  if (value[0] !== bullet) {
    target.value = `${bulletWithSpace}${value}`;
  }
}
