
/*

    Copyright © 2016, Lightfactor, LLC.
    Created by Dave Atherton.

    This file is part of lightfactor-uaf.

    lightfactor-uaf is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    lightfactor-uaf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

var Canvas = require('canvas');
var Image = Canvas.Image;
var fs = require('fs');
//var PNG = require('pngjs').PNG;
//var PassThroughStream = require('stream').PassThrough;

//console.log(canvas.toBuffer());

/*
var stream = canvas.pngStream();
var out = fs.createWriteStream(__dirname + '/text.png');

stream.on('data', function(chunk){
  out.write(chunk);
});

stream.on('end', function(){
  out.close();
  console.log('saved png');
});
*/

/*
var bufferStream = new PassThroughStream();
bufferStream.end(buffer);

bufferStream
//fs.createReadStream('in.png')
    .pipe(new PNG( { colorType: 2, bgColor: { red: 255, green: 0, blue: 0 } } ))
    .on('parsed', function() {
//        var btest = PNG.sync.write(this.pack());
//        console.log(btest.length);
//        fs.writeFileSync('btest.png', btest);
        this.pack().pipe(fs.createWriteStream('out.png'));
    });

var bufferStream2 = new PassThroughStream();
var resizedBuffer = resize(buffer, 300, 500).toBuffer()
bufferStream2.end(resizedBuffer);

bufferStream2
//fs.createReadStream('in.png')
    .pipe(new PNG( {  } ))      // colorType: 2, bgColor: { red: 255, green: 0, blue: 0 }
    .on('parsed', function() {
//        this.adjustGamma();
        this.pack().pipe(fs.createWriteStream('resized.png'));
    });


//console.log(canvas.toDataURL());

*/

function getFontString(font) {
  var fontString = `${font.weight} ${font.style} ${font.size}${font.unit} ${font.family}`;
  return fontString;
}

function createImageFromText(text, targetWidth, targetHeight) {

  var font = {              // taken from context2d.js...
    weight: 'normal',           // normal|bold|bolder|lighter|[1-9]00
    style: 'normal',          // normal|italic|oblique
    size: 30,
    unit: 'px',               // px|pt|pc|in|cm|mm|%
    family: 'helvetica'
  };

  var options = {
    textColor: 'white',
    bgColor: 'black',
    lineSpacing: 0,
    padding: 20
  };

  const canvas = new Canvas(0, 0);
  const ctx = canvas.getContext('2d');

  const max = {
    left: 0,
    right: 0,
    ascent: 0,
    descent: 0
  };

  let lastDescent;
  const lineProps = text.split('\n').map(line => {
    ctx.font = getFontString(font);
    ctx.textAlign = 'left';
    const metrics = ctx.measureText(line);

    const left = -1 * metrics.actualBoundingBoxLeft;
    const right = metrics.actualBoundingBoxRight;
    const ascent = metrics.actualBoundingBoxAscent;
    const descent = metrics.actualBoundingBoxDescent;

    max.left = Math.max(max.left, left);
    max.right = Math.max(max.right, right);
    max.ascent = Math.max(max.ascent, ascent);
    max.descent = Math.max(max.descent, descent);
    lastDescent = descent;

    return {line, left, ascent};
  });

  var logo = fs.readFileSync(__dirname + '/logo.png');
  var img = new Image();
  img.src = logo;

  canvas.width = targetWidth;
  canvas.height = targetHeight;

  ctx.fillStyle = options.bgColor;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, targetWidth/2-(img.width/3), targetHeight - img.height, img.width, img.height);

  targetHeight = targetHeight - img.height;         // adjust for watermark in margin at bottom for autofit math below

  const lineHeight = max.ascent + max.descent + options.lineSpacing;
  var rawWidth = max.left + max.right + options.padding * 2;
  var rawHeight = lineHeight * lineProps.length + options.padding * 2 - options.lineSpacing - (max.descent - lastDescent);
  var rawR = rawWidth / rawHeight;
  var targetR = targetWidth / targetHeight;
  var calcWidth = (targetR > rawR) ? Math.floor(rawWidth * (targetHeight / rawHeight)) : targetWidth;
  var calcHeight = (targetR > rawR) ? targetHeight : Math.floor(rawHeight * (targetWidth / rawWidth));
  var hFactor = 1.0 * calcHeight/rawHeight;
  var wFactor = 1.0 * calcWidth/rawWidth;
  var hFactorAdj = Math.abs(Math.log(hFactor));
  var wFactorAdj = Math.abs(Math.log(wFactor));

  var factor = (hFactorAdj > wFactorAdj) ? wFactor : hFactor;

  font.size = font.size * factor;
  ctx.font = getFontString(font);
  ctx.fillStyle = options.textColor;
  ctx.antialias = 'subpixel';         // default, none, gray, subpixel
  let offsetY = options.padding;
  lineProps.forEach(lineProp => {
    ctx.fillText(lineProp.line, lineProp.left + options.padding, max.ascent*factor + offsetY);
    offsetY += lineHeight*factor;
  });

  return canvas;
//  return canvas.toBuffer();
//  return canvas.createPNGStream();
//  return canvas.toDataURL('image/png');
/*
  var img = new Image();
  var canvasResized = new Canvas(targetWidth, targetHeight);
  var ctxResized = canvasResized.getContext('2d');

  img.src = (canvas.toBuffer());
  ctxResized.imageSmoothingEnabled = true;
  ctxResized.drawImage(img, 0, 0, targetWidth, targetWidth);
// evaluate ctx.createImageData(width, height) for use with pngjs

  return canvasResized;
*/
}

/*

// see https://www.w3.org/TR/PNG/#11IHDR for allowable values

// for colorType/bitDepths:

// PNG Image Type           cT  allowed BD                  Comment
// -----------------------  --  --------------------------  -------------------------------------------------------------
// Greyscale                0   1, 2, 4, 8, 16              Each pixel is a greyscale sample; PLTE shall not appear.
// Truecolour               2   8, 16                       Each pixel is an R,G,B triple; PLTE may appear.
// Indexed-colour           3   1, 2, 4, 8                  Each pixel is a palette index; a PLTE chunk shall appear.
// Greyscale with alpha     4   8, 16                       Each pixel is a greyscale sample followed by an alpha sample; PLTE shall not appear.
// Truecolour with alpha    6   8, 16                       Each pixel is an R,G,B triple followed by an alpha sample; PLTE may appear.


// from https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-authnr-metadata-v1.0-ps-20141208.html#idl-def-DisplayPNGCharacteristicsDescriptor
// for UAF transaction confirmation, from authenticator metadata:

dictionary DisplayPNGCharacteristicsDescriptor {
    required unsigned long width;
    required unsigned long height;
    required octet         bitDepth;                        // 1, 2, 4, 8, 16 (see above)
    required octet         colorType;                       // 0, 2, 3, 4, 6 (see above)
    required octet         compression;                     // always 0 per PNG spec (only 0 is defined)
    required octet         filter;                          // always 0 per PNG spec (only 0 is defined)
    required octet         interlace;                       // 0 (null method) or 1 ("Adam7") are defined
    rgbPalletteEntry[]     plte;
};

dictionary rgbPalletteEntry {
    required unsigned short r;
    required unsigned short g;
    required unsigned short b;
};


// Qiwi:

"tcDisplayContentType"    : "image/png",
"tcDisplayPNGCharacteristics"  : [
  {
    "width":200,
    "height":400,
    "bitDepth":8,
    "colorType":6,
    "compression":0,
    "filter":0,
    "interlace":0
  },
  {
    "width":300,
    "height":500,
    "bitDepth":8,
    "colorType":6,
    "compression":0,
    "filter":0,
    "interlace":0
  }
]


*/

module.exports = {
  createImageFromText: createImageFromText
};
