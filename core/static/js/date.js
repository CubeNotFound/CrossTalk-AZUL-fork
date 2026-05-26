var dayOfWeek = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
var monthOfYear = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

var today = new Date();
var year = today.getFullYear();

document.write("<p class=datetext><b>Today is:</b></p><font color=gray><i>" + dayOfWeek[today.getDay()] + ", " + monthOfYear[today.getMonth()] + " " + today.getDate() + ", " + year + "</font></i></p>");