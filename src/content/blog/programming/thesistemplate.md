---
title: "Thesis Template conf.typ"
description: "Ajdust it with your own uni"
date: "2025-5-14"
---
```typ
#import "@preview/i-figured:0.2.4"

#let title-case(string) = {
  return string.replace(
    regex("[A-Za-z]+('[A-Za-z]+)?"),
    word => upper(word.text.first()) + lower(word.text.slice(1)),
  )
}

#let sampul(
  judul: "JUDUL BAHASA INDONESIA",
  judul-english: "JUDUL BAHASA INGGRIS",
  nama: "NAMA MAHASISWA",
  nim: "NIM",
  prodi: "PROGRAM STUDI",
  fakultas: "FAKULTAS",
  tahun: "Tahun",
) = {
  align(center)[
    *SKRIPSI*\ \ \
    *#judul*\ \
    #emph[*#judul-english*]
    #v(6em)
    #image("media/image1.jpg", width: 3.59cm, height: 3.66cm)
    #v(6em)

    #nama

    #nim

    #v(8em)

    *#prodi*\
    *#fakultas*\
    *UNIVERSITAS GADJAH MADA*\
    *YOGYAKARTA*
    #v(2em)
    *#tahun*
    #pagebreak()
  ]
}

#let sampul2(
  judul: "JUDUL BAHASA INDONESIA",
  judul-english: "JUDUL BAHASA INGGRIS",
  nama: "NAMA MAHASISWA",
  nim: "NIM",
  prodi: "PROGRAM STUDI",
  fakultas: "FAKULTAS",
  tahun: "Tahun",
) = {
  align(center)[
    *SKRIPSI*\ \ \
    *#judul*\ \
    #emph[*#judul-english*]
    #v(4em)
    Diajukan untuk memenuhi salah satu syarat memperoleh derajat\
    Sarjana #title-case(prodi)
    #v(4em)
    #image("media/image1.jpg", width: 3.59cm, height: 3.66cm)
    #v(4em)

    #nama

    #nim

    #v(5em)

    *#prodi*\
    *#fakultas*\
    *UNIVERSITAS GADJAH MADA*\
    *YOGYAKARTA*
    #v(2em)
    *#tahun*
    #pagebreak()
  ]
}

#let pengesahan(
  judul: "JUDUL BAHASA INDONESIA",
  nama: "NAMA MAHASISWA",
  nim: "NIM",
  tgl-pengesahan: "17 Agustus 1945",
) = {
  align(center)[
    = HALAMAN PENGESAHAN
    *SKRIPSI*\ \
    *#judul*\ \
    Telah dipersiapkan dan disusun oleh\
    #nama\
    #nim
    #v(3em)
    Telah dipertahankan di depan Tim Penguji\
    pada tanggal #tgl-pengesahan
    #v(3em)
    Susunan Tim Penguji:

    #let ttd-gap = [#v(6em)]
    #table(
      columns: (1fr, 1fr),
      stroke: none,
      [
        #ttd-gap
        Nama Pembimbing I\
        Pembimbing I/Penguji
      ],
      [
        #ttd-gap
        Nama Penguji I\
        Penguji
      ],

      [
        #ttd-gap
        Nama Pembimbing II\
        Pembimbing II/Penguji
      ],
      [
        #ttd-gap
        Nama Penguji II\
        Penguji
      ],

      [
        #ttd-gap
      ],
      [
        #ttd-gap
        Nama Penguji III\
        Penguji
      ],
    )
  ]
  pagebreak()
}

#let pernyataan(
  konten: lorem(100),
  tanggal: "17 Agustus 1945",
  nama: "NAMA MAHASISWA",
) = {
  align(center)[
    = PERNYATAAN
  ]
  konten
  v(2em)
  align(right)[
    Yogyakarta, #tanggal\
    #v(5em)
    #title-case(nama)
  ]
  pagebreak()
}

#let daftar = [
  = DAFTAR ISI
  #outline(title: none, indent: 1em)
  #pagebreak()

  = DAFTAR TABEL
  #outline(target: figure.where(kind: table), title: none)
  #pagebreak()

  = DAFTAR GAMBAR
  #i-figured.outline(title: none)
  #pagebreak()

  = DAFTAR SIMBOL
  #pagebreak()
]

#let intisari-gen(
  judul: "Konsep dan Pemodelan Berorientasi-Aspek Menggunakan UML dalam AspectJ",
  nama: "Nama Mahasiswa",
  nim: "22/504395/PA/21696",
  konten: [
    #lorem(100)

    #lorem(100)],
) = [
  #align(center)[
    = INTISARI
    #v(1em)
    *#judul*
    #v(1em)
    Oleh
    #v(1em)
    #nama #nim
    #v(1em)
  ]

  #konten
  #pagebreak()
]

#let abstract-gen(
  title: "Aspect-Oriented Concepts and UML Modeling on AspectJ",
  name: "Nama Mahasiswa",
  nim: "22/504395/PA/21696",
  content: [
    #lorem(100)

    #lorem(100)],
) = [
  #align(center)[
    = #emph[ABSTRACT]
    #v(1em)
    *#title*
    #v(1em)
    Oleh
    #v(1em)
    #name #nim
    #v(1em)
  ]

  #content
  #pagebreak()
]


#let conf(
  judul: "JUDUL BAHASA INDONESIA",
  judul-english: "JUDUL BAHASA INGGRIS",
  nama: "NAMA MAHASISWA",
  nim: "NIM",
  prodi: "PROGRAM STUDI",
  fakultas: "FAKULTAS",
  tahun: "Tahun",
  tgl-pengesahan: "17 Agustus 1945",
  tgl-pernyataan: "17 Agustus 1945",
  intisari: [
    #lorem(100)

    #lorem(100)
  ],
  abstract: [
    #lorem(100)

    #lorem(100)
  ],
  doc,
) = {
  set page(
    paper: "a4",
    margin: (
      top: 4cm,
      bottom: 3cm,
      left: 4cm,
      right: 3cm,
    ),
  )
  set text(font: "Times New Roman", size: 12pt, hyphenate: false)

  sampul(
    judul: judul,
    judul-english: judul-english,
    nama: nama,
    nim: nim,
    prodi: prodi,
    fakultas: fakultas,
    tahun: tahun,
  )
  // #let leading = 1.5em
  // #let leading = leading - 0.75em // "Normalization"
  // #set block(spacing: leading)
  // #set par(leading: leading)

  set page(numbering: "1")
  set image(width: 8.84cm)
  show heading: set block(below: 1.13em) //TODO: refine
  show heading.where(level: 1): set text(weight: "bold", size: 14pt)
  show heading.where(level: 1): set align(center)
  show heading.where(level: 1): set block(below: 1.5em) //TODO: refine
  show heading.where(level: 2): set text(weight: "bold", size: 12pt)
  show figure.where(kind: image): set figure(supplement: "Gambar")
  show figure.where(kind: table): set figure(supplement: "Tabel")
  show figure: i-figured.show-figure
  show figure.where(kind: table): set figure.caption(position: top)
  show figure.caption: c => [
    #show regex(".*:"): set text(weight: "bold")
    #show ":": ""
    #c
  ]

  counter(page).update(1)

  sampul2(
    judul: judul,
    judul-english: judul-english,
    nama: nama,
    nim: nim,
    prodi: prodi,
    fakultas: fakultas,
    tahun: tahun,
  )
  pengesahan(
    judul: judul,
    nama: nama,
    nim: nim,
    tgl-pengesahan: tgl-pengesahan,
  )

  set par(
    first-line-indent: (amount: 1.48cm, all: true),
    justify: true,
    leading: 1.14em,
    spacing: 1.5em,
    // leading: 1.5em - 0.75em,
    // spacing: 2.5em - 0.75em,
  ) //TODO:refine leading

  pernyataan(
    tanggal: tgl-pernyataan,
    nama: nama,
  )

  daftar

  intisari-gen(
    judul: title-case(judul),
    nama: title-case(nama),
    nim: nim,
    konten: intisari,
  )

  abstract-gen(
    title: title-case(judul-english),
    name: title-case(nama),
    nim: nim,
    content: abstract,
  )

  counter(heading).update(0)

  set heading(
    numbering: (..numbers) => if numbers.pos().len() > 1 {
      return numbering("1.1", ..numbers)
    } else {
      return text[BAB #numbers.pos().last()]
    },
  )

  doc
}
```
