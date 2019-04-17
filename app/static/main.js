// make sure the DOM loads first
document.addEventListener("DOMContentLoaded", function() {


  function start(){

  window.timerID =  setInterval(function() {
  var aOpaque = document.getElementById('imageID').style.opacity;
  aOpaque = aOpaque-.1;

  aOpaque = aOpaque.toFixed(1);

  document.getElementById('imageID').style.opacity = aOpaque;

  if(document.getElementById('imageID').style.opacity<=0)
  clearInterval(window.timerID);
  },1000);
  }

  window.onload = function(){start();}

//   // CKEDITOR.replace('body')
//
//   // Not needed for now
//   var navContainer = document.getElementById("navUl");
//   var links = navContainer.getElementsByClassName("link")
//
//   for(var i=0; i<links.length; i++) {
//     links[i].addEventListener("click", function() {
//       var current = document.getElementsByClassName("active");
//       current[0].className = current[0].className.replace(" active", "");
//       this.className += " active";
//     });
//   }
//
//   // TODO:
//   // flash animations!!!
});
