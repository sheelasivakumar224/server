require('dotenv').config();
const myVariable = process.env.SERVER;

if (myVariable) {
  console.log(`The value of MY_VARIABLE is: ${myVariable}`);
} else {
  console.log('MY_VARIABLE is not set.');
}