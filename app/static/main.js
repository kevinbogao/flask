// Ensure the DOM is loaded first
document.addEventListener("DOMContentLoaded", function() {

  // replace textarea with CKEDITOR
  CKEDITOR.replace("body");

  // responsive
  function myFunction() {
    var x = document.getElementById("topnav");
    if (x.className === "topnav") {
      x.className += " responsive";
    } else {
      x.className = "topnav";
    }
  }

});
