﻿Imports System.Security.Cryptography
Imports System.IO

Public Class Encryption

    Public Function RunAES(sFile As String, bEncrpyt As Boolean, encryptKey As String) As String
        Dim sbox, sboxinv, rcon
        Dim g2, g3, g9, g11, g13, g14

        Dim expandedKey, block(16), aesKey(32), i, isDone, j, isEncode
        Dim sPlain, sPass, sCipher, sTemp, nonce(16), priorCipher(16)
        Dim x, r, y, temp(4), intTemp

        g2 = { _
            &H0, &H2, &H4, &H6, &H8, &HA, &HC, &HE, &H10, &H12, &H14, &H16, &H18, &H1A, &H1C, &H1E, _
            &H20, &H22, &H24, &H26, &H28, &H2A, &H2C, &H2E, &H30, &H32, &H34, &H36, &H38, &H3A, &H3C, &H3E, _
            &H40, &H42, &H44, &H46, &H48, &H4A, &H4C, &H4E, &H50, &H52, &H54, &H56, &H58, &H5A, &H5C, &H5E, _
            &H60, &H62, &H64, &H66, &H68, &H6A, &H6C, &H6E, &H70, &H72, &H74, &H76, &H78, &H7A, &H7C, &H7E, _
            &H80, &H82, &H84, &H86, &H88, &H8A, &H8C, &H8E, &H90, &H92, &H94, &H96, &H98, &H9A, &H9C, &H9E, _
            &HA0, &HA2, &HA4, &HA6, &HA8, &HAA, &HAC, &HAE, &HB0, &HB2, &HB4, &HB6, &HB8, &HBA, &HBC, &HBE, _
            &HC0, &HC2, &HC4, &HC6, &HC8, &HCA, &HCC, &HCE, &HD0, &HD2, &HD4, &HD6, &HD8, &HDA, &HDC, &HDE, _
            &HE0, &HE2, &HE4, &HE6, &HE8, &HEA, &HEC, &HEE, &HF0, &HF2, &HF4, &HF6, &HF8, &HFA, &HFC, &HFE, _
            &H1B, &H19, &H1F, &H1D, &H13, &H11, &H17, &H15, &HB, &H9, &HF, &HD, &H3, &H1, &H7, &H5, _
            &H3B, &H39, &H3F, &H3D, &H33, &H31, &H37, &H35, &H2B, &H29, &H2F, &H2D, &H23, &H21, &H27, &H25, _
            &H5B, &H59, &H5F, &H5D, &H53, &H51, &H57, &H55, &H4B, &H49, &H4F, &H4D, &H43, &H41, &H47, &H45, _
            &H7B, &H79, &H7F, &H7D, &H73, &H71, &H77, &H75, &H6B, &H69, &H6F, &H6D, &H63, &H61, &H67, &H65, _
            &H9B, &H99, &H9F, &H9D, &H93, &H91, &H97, &H95, &H8B, &H89, &H8F, &H8D, &H83, &H81, &H87, &H85, _
            &HBB, &HB9, &HBF, &HBD, &HB3, &HB1, &HB7, &HB5, &HAB, &HA9, &HAF, &HAD, &HA3, &HA1, &HA7, &HA5, _
            &HDB, &HD9, &HDF, &HDD, &HD3, &HD1, &HD7, &HD5, &HCB, &HC9, &HCF, &HCD, &HC3, &HC1, &HC7, &HC5, _
            &HFB, &HF9, &HFF, &HFD, &HF3, &HF1, &HF7, &HF5, &HEB, &HE9, &HEF, &HED, &HE3, &HE1, &HE7, &HE5}

        g3 = { _
            &H0, &H3, &H6, &H5, &HC, &HF, &HA, &H9, &H18, &H1B, &H1E, &H1D, &H14, &H17, &H12, &H11, _
            &H30, &H33, &H36, &H35, &H3C, &H3F, &H3A, &H39, &H28, &H2B, &H2E, &H2D, &H24, &H27, &H22, &H21, _
            &H60, &H63, &H66, &H65, &H6C, &H6F, &H6A, &H69, &H78, &H7B, &H7E, &H7D, &H74, &H77, &H72, &H71, _
            &H50, &H53, &H56, &H55, &H5C, &H5F, &H5A, &H59, &H48, &H4B, &H4E, &H4D, &H44, &H47, &H42, &H41, _
            &HC0, &HC3, &HC6, &HC5, &HCC, &HCF, &HCA, &HC9, &HD8, &HDB, &HDE, &HDD, &HD4, &HD7, &HD2, &HD1, _
            &HF0, &HF3, &HF6, &HF5, &HFC, &HFF, &HFA, &HF9, &HE8, &HEB, &HEE, &HED, &HE4, &HE7, &HE2, &HE1, _
            &HA0, &HA3, &HA6, &HA5, &HAC, &HAF, &HAA, &HA9, &HB8, &HBB, &HBE, &HBD, &HB4, &HB7, &HB2, &HB1, _
            &H90, &H93, &H96, &H95, &H9C, &H9F, &H9A, &H99, &H88, &H8B, &H8E, &H8D, &H84, &H87, &H82, &H81, _
            &H9B, &H98, &H9D, &H9E, &H97, &H94, &H91, &H92, &H83, &H80, &H85, &H86, &H8F, &H8C, &H89, &H8A, _
            &HAB, &HA8, &HAD, &HAE, &HA7, &HA4, &HA1, &HA2, &HB3, &HB0, &HB5, &HB6, &HBF, &HBC, &HB9, &HBA, _
            &HFB, &HF8, &HFD, &HFE, &HF7, &HF4, &HF1, &HF2, &HE3, &HE0, &HE5, &HE6, &HEF, &HEC, &HE9, &HEA, _
            &HCB, &HC8, &HCD, &HCE, &HC7, &HC4, &HC1, &HC2, &HD3, &HD0, &HD5, &HD6, &HDF, &HDC, &HD9, &HDA, _
            &H5B, &H58, &H5D, &H5E, &H57, &H54, &H51, &H52, &H43, &H40, &H45, &H46, &H4F, &H4C, &H49, &H4A, _
            &H6B, &H68, &H6D, &H6E, &H67, &H64, &H61, &H62, &H73, &H70, &H75, &H76, &H7F, &H7C, &H79, &H7A, _
            &H3B, &H38, &H3D, &H3E, &H37, &H34, &H31, &H32, &H23, &H20, &H25, &H26, &H2F, &H2C, &H29, &H2A, _
            &HB, &H8, &HD, &HE, &H7, &H4, &H1, &H2, &H13, &H10, &H15, &H16, &H1F, &H1C, &H19, &H1A}

        g9 = { _
            &H0, &H9, &H12, &H1B, &H24, &H2D, &H36, &H3F, &H48, &H41, &H5A, &H53, &H6C, &H65, &H7E, &H77, _
            &H90, &H99, &H82, &H8B, &HB4, &HBD, &HA6, &HAF, &HD8, &HD1, &HCA, &HC3, &HFC, &HF5, &HEE, &HE7, _
            &H3B, &H32, &H29, &H20, &H1F, &H16, &HD, &H4, &H73, &H7A, &H61, &H68, &H57, &H5E, &H45, &H4C, _
            &HAB, &HA2, &HB9, &HB0, &H8F, &H86, &H9D, &H94, &HE3, &HEA, &HF1, &HF8, &HC7, &HCE, &HD5, &HDC, _
            &H76, &H7F, &H64, &H6D, &H52, &H5B, &H40, &H49, &H3E, &H37, &H2C, &H25, &H1A, &H13, &H8, &H1, _
            &HE6, &HEF, &HF4, &HFD, &HC2, &HCB, &HD0, &HD9, &HAE, &HA7, &HBC, &HB5, &H8A, &H83, &H98, &H91, _
            &H4D, &H44, &H5F, &H56, &H69, &H60, &H7B, &H72, &H5, &HC, &H17, &H1E, &H21, &H28, &H33, &H3A, _
            &HDD, &HD4, &HCF, &HC6, &HF9, &HF0, &HEB, &HE2, &H95, &H9C, &H87, &H8E, &HB1, &HB8, &HA3, &HAA, _
            &HEC, &HE5, &HFE, &HF7, &HC8, &HC1, &HDA, &HD3, &HA4, &HAD, &HB6, &HBF, &H80, &H89, &H92, &H9B, _
            &H7C, &H75, &H6E, &H67, &H58, &H51, &H4A, &H43, &H34, &H3D, &H26, &H2F, &H10, &H19, &H2, &HB, _
            &HD7, &HDE, &HC5, &HCC, &HF3, &HFA, &HE1, &HE8, &H9F, &H96, &H8D, &H84, &HBB, &HB2, &HA9, &HA0, _
            &H47, &H4E, &H55, &H5C, &H63, &H6A, &H71, &H78, &HF, &H6, &H1D, &H14, &H2B, &H22, &H39, &H30, _
            &H9A, &H93, &H88, &H81, &HBE, &HB7, &HAC, &HA5, &HD2, &HDB, &HC0, &HC9, &HF6, &HFF, &HE4, &HED, _
            &HA, &H3, &H18, &H11, &H2E, &H27, &H3C, &H35, &H42, &H4B, &H50, &H59, &H66, &H6F, &H74, &H7D, _
            &HA1, &HA8, &HB3, &HBA, &H85, &H8C, &H97, &H9E, &HE9, &HE0, &HFB, &HF2, &HCD, &HC4, &HDF, &HD6, _
            &H31, &H38, &H23, &H2A, &H15, &H1C, &H7, &HE, &H79, &H70, &H6B, &H62, &H5D, &H54, &H4F, &H46}

        g11 = { _
            &H0, &HB, &H16, &H1D, &H2C, &H27, &H3A, &H31, &H58, &H53, &H4E, &H45, &H74, &H7F, &H62, &H69, _
            &HB0, &HBB, &HA6, &HAD, &H9C, &H97, &H8A, &H81, &HE8, &HE3, &HFE, &HF5, &HC4, &HCF, &HD2, &HD9, _
            &H7B, &H70, &H6D, &H66, &H57, &H5C, &H41, &H4A, &H23, &H28, &H35, &H3E, &HF, &H4, &H19, &H12, _
            &HCB, &HC0, &HDD, &HD6, &HE7, &HEC, &HF1, &HFA, &H93, &H98, &H85, &H8E, &HBF, &HB4, &HA9, &HA2, _
            &HF6, &HFD, &HE0, &HEB, &HDA, &HD1, &HCC, &HC7, &HAE, &HA5, &HB8, &HB3, &H82, &H89, &H94, &H9F, _
            &H46, &H4D, &H50, &H5B, &H6A, &H61, &H7C, &H77, &H1E, &H15, &H8, &H3, &H32, &H39, &H24, &H2F, _
            &H8D, &H86, &H9B, &H90, &HA1, &HAA, &HB7, &HBC, &HD5, &HDE, &HC3, &HC8, &HF9, &HF2, &HEF, &HE4, _
            &H3D, &H36, &H2B, &H20, &H11, &H1A, &H7, &HC, &H65, &H6E, &H73, &H78, &H49, &H42, &H5F, &H54, _
            &HF7, &HFC, &HE1, &HEA, &HDB, &HD0, &HCD, &HC6, &HAF, &HA4, &HB9, &HB2, &H83, &H88, &H95, &H9E, _
            &H47, &H4C, &H51, &H5A, &H6B, &H60, &H7D, &H76, &H1F, &H14, &H9, &H2, &H33, &H38, &H25, &H2E, _
            &H8C, &H87, &H9A, &H91, &HA0, &HAB, &HB6, &HBD, &HD4, &HDF, &HC2, &HC9, &HF8, &HF3, &HEE, &HE5, _
            &H3C, &H37, &H2A, &H21, &H10, &H1B, &H6, &HD, &H64, &H6F, &H72, &H79, &H48, &H43, &H5E, &H55, _
            &H1, &HA, &H17, &H1C, &H2D, &H26, &H3B, &H30, &H59, &H52, &H4F, &H44, &H75, &H7E, &H63, &H68, _
            &HB1, &HBA, &HA7, &HAC, &H9D, &H96, &H8B, &H80, &HE9, &HE2, &HFF, &HF4, &HC5, &HCE, &HD3, &HD8, _
            &H7A, &H71, &H6C, &H67, &H56, &H5D, &H40, &H4B, &H22, &H29, &H34, &H3F, &HE, &H5, &H18, &H13, _
            &HCA, &HC1, &HDC, &HD7, &HE6, &HED, &HF0, &HFB, &H92, &H99, &H84, &H8F, &HBE, &HB5, &HA8, &HA3}

        g13 = { _
            &H0, &HD, &H1A, &H17, &H34, &H39, &H2E, &H23, &H68, &H65, &H72, &H7F, &H5C, &H51, &H46, &H4B, _
            &HD0, &HDD, &HCA, &HC7, &HE4, &HE9, &HFE, &HF3, &HB8, &HB5, &HA2, &HAF, &H8C, &H81, &H96, &H9B, _
            &HBB, &HB6, &HA1, &HAC, &H8F, &H82, &H95, &H98, &HD3, &HDE, &HC9, &HC4, &HE7, &HEA, &HFD, &HF0, _
            &H6B, &H66, &H71, &H7C, &H5F, &H52, &H45, &H48, &H3, &HE, &H19, &H14, &H37, &H3A, &H2D, &H20, _
            &H6D, &H60, &H77, &H7A, &H59, &H54, &H43, &H4E, &H5, &H8, &H1F, &H12, &H31, &H3C, &H2B, &H26, _
            &HBD, &HB0, &HA7, &HAA, &H89, &H84, &H93, &H9E, &HD5, &HD8, &HCF, &HC2, &HE1, &HEC, &HFB, &HF6, _
            &HD6, &HDB, &HCC, &HC1, &HE2, &HEF, &HF8, &HF5, &HBE, &HB3, &HA4, &HA9, &H8A, &H87, &H90, &H9D, _
            &H6, &HB, &H1C, &H11, &H32, &H3F, &H28, &H25, &H6E, &H63, &H74, &H79, &H5A, &H57, &H40, &H4D, _
            &HDA, &HD7, &HC0, &HCD, &HEE, &HE3, &HF4, &HF9, &HB2, &HBF, &HA8, &HA5, &H86, &H8B, &H9C, &H91, _
            &HA, &H7, &H10, &H1D, &H3E, &H33, &H24, &H29, &H62, &H6F, &H78, &H75, &H56, &H5B, &H4C, &H41, _
            &H61, &H6C, &H7B, &H76, &H55, &H58, &H4F, &H42, &H9, &H4, &H13, &H1E, &H3D, &H30, &H27, &H2A, _
            &HB1, &HBC, &HAB, &HA6, &H85, &H88, &H9F, &H92, &HD9, &HD4, &HC3, &HCE, &HED, &HE0, &HF7, &HFA, _
            &HB7, &HBA, &HAD, &HA0, &H83, &H8E, &H99, &H94, &HDF, &HD2, &HC5, &HC8, &HEB, &HE6, &HF1, &HFC, _
            &H67, &H6A, &H7D, &H70, &H53, &H5E, &H49, &H44, &HF, &H2, &H15, &H18, &H3B, &H36, &H21, &H2C, _
            &HC, &H1, &H16, &H1B, &H38, &H35, &H22, &H2F, &H64, &H69, &H7E, &H73, &H50, &H5D, &H4A, &H47, _
            &HDC, &HD1, &HC6, &HCB, &HE8, &HE5, &HF2, &HFF, &HB4, &HB9, &HAE, &HA3, &H80, &H8D, &H9A, &H97}

        g14 = { _
            &H0, &HE, &H1C, &H12, &H38, &H36, &H24, &H2A, &H70, &H7E, &H6C, &H62, &H48, &H46, &H54, &H5A, _
            &HE0, &HEE, &HFC, &HF2, &HD8, &HD6, &HC4, &HCA, &H90, &H9E, &H8C, &H82, &HA8, &HA6, &HB4, &HBA, _
            &HDB, &HD5, &HC7, &HC9, &HE3, &HED, &HFF, &HF1, &HAB, &HA5, &HB7, &HB9, &H93, &H9D, &H8F, &H81, _
            &H3B, &H35, &H27, &H29, &H3, &HD, &H1F, &H11, &H4B, &H45, &H57, &H59, &H73, &H7D, &H6F, &H61, _
            &HAD, &HA3, &HB1, &HBF, &H95, &H9B, &H89, &H87, &HDD, &HD3, &HC1, &HCF, &HE5, &HEB, &HF9, &HF7, _
            &H4D, &H43, &H51, &H5F, &H75, &H7B, &H69, &H67, &H3D, &H33, &H21, &H2F, &H5, &HB, &H19, &H17, _
            &H76, &H78, &H6A, &H64, &H4E, &H40, &H52, &H5C, &H6, &H8, &H1A, &H14, &H3E, &H30, &H22, &H2C, _
            &H96, &H98, &H8A, &H84, &HAE, &HA0, &HB2, &HBC, &HE6, &HE8, &HFA, &HF4, &HDE, &HD0, &HC2, &HCC, _
            &H41, &H4F, &H5D, &H53, &H79, &H77, &H65, &H6B, &H31, &H3F, &H2D, &H23, &H9, &H7, &H15, &H1B, _
            &HA1, &HAF, &HBD, &HB3, &H99, &H97, &H85, &H8B, &HD1, &HDF, &HCD, &HC3, &HE9, &HE7, &HF5, &HFB, _
            &H9A, &H94, &H86, &H88, &HA2, &HAC, &HBE, &HB0, &HEA, &HE4, &HF6, &HF8, &HD2, &HDC, &HCE, &HC0, _
            &H7A, &H74, &H66, &H68, &H42, &H4C, &H5E, &H50, &HA, &H4, &H16, &H18, &H32, &H3C, &H2E, &H20, _
            &HEC, &HE2, &HF0, &HFE, &HD4, &HDA, &HC8, &HC6, &H9C, &H92, &H80, &H8E, &HA4, &HAA, &HB8, &HB6, _
            &HC, &H2, &H10, &H1E, &H34, &H3A, &H28, &H26, &H7C, &H72, &H60, &H6E, &H44, &H4A, &H58, &H56, _
            &H37, &H39, &H2B, &H25, &HF, &H1, &H13, &H1D, &H47, &H49, &H5B, &H55, &H7F, &H71, &H63, &H6D, _
            &HD7, &HD9, &HCB, &HC5, &HEF, &HE1, &HF3, &HFD, &HA7, &HA9, &HBB, &HB5, &H9F, &H91, &H83, &H8D}

        sbox = { _
            &H63, &H7C, &H77, &H7B, &HF2, &H6B, &H6F, &HC5, &H30, &H1, &H67, &H2B, &HFE, &HD7, &HAB, &H76, _
            &HCA, &H82, &HC9, &H7D, &HFA, &H59, &H47, &HF0, &HAD, &HD4, &HA2, &HAF, &H9C, &HA4, &H72, &HC0, _
            &HB7, &HFD, &H93, &H26, &H36, &H3F, &HF7, &HCC, &H34, &HA5, &HE5, &HF1, &H71, &HD8, &H31, &H15, _
            &H4, &HC7, &H23, &HC3, &H18, &H96, &H5, &H9A, &H7, &H12, &H80, &HE2, &HEB, &H27, &HB2, &H75, _
            &H9, &H83, &H2C, &H1A, &H1B, &H6E, &H5A, &HA0, &H52, &H3B, &HD6, &HB3, &H29, &HE3, &H2F, &H84, _
            &H53, &HD1, &H0, &HED, &H20, &HFC, &HB1, &H5B, &H6A, &HCB, &HBE, &H39, &H4A, &H4C, &H58, &HCF, _
            &HD0, &HEF, &HAA, &HFB, &H43, &H4D, &H33, &H85, &H45, &HF9, &H2, &H7F, &H50, &H3C, &H9F, &HA8, _
            &H51, &HA3, &H40, &H8F, &H92, &H9D, &H38, &HF5, &HBC, &HB6, &HDA, &H21, &H10, &HFF, &HF3, &HD2, _
            &HCD, &HC, &H13, &HEC, &H5F, &H97, &H44, &H17, &HC4, &HA7, &H7E, &H3D, &H64, &H5D, &H19, &H73, _
            &H60, &H81, &H4F, &HDC, &H22, &H2A, &H90, &H88, &H46, &HEE, &HB8, &H14, &HDE, &H5E, &HB, &HDB, _
            &HE0, &H32, &H3A, &HA, &H49, &H6, &H24, &H5C, &HC2, &HD3, &HAC, &H62, &H91, &H95, &HE4, &H79, _
            &HE7, &HC8, &H37, &H6D, &H8D, &HD5, &H4E, &HA9, &H6C, &H56, &HF4, &HEA, &H65, &H7A, &HAE, &H8, _
            &HBA, &H78, &H25, &H2E, &H1C, &HA6, &HB4, &HC6, &HE8, &HDD, &H74, &H1F, &H4B, &HBD, &H8B, &H8A, _
            &H70, &H3E, &HB5, &H66, &H48, &H3, &HF6, &HE, &H61, &H35, &H57, &HB9, &H86, &HC1, &H1D, &H9E, _
            &HE1, &HF8, &H98, &H11, &H69, &HD9, &H8E, &H94, &H9B, &H1E, &H87, &HE9, &HCE, &H55, &H28, &HDF, _
            &H8C, &HA1, &H89, &HD, &HBF, &HE6, &H42, &H68, &H41, &H99, &H2D, &HF, &HB0, &H54, &HBB, &H16}

        sboxinv = { _
            &H52, &H9, &H6A, &HD5, &H30, &H36, &HA5, &H38, &HBF, &H40, &HA3, &H9E, &H81, &HF3, &HD7, &HFB, _
            &H7C, &HE3, &H39, &H82, &H9B, &H2F, &HFF, &H87, &H34, &H8E, &H43, &H44, &HC4, &HDE, &HE9, &HCB, _
            &H54, &H7B, &H94, &H32, &HA6, &HC2, &H23, &H3D, &HEE, &H4C, &H95, &HB, &H42, &HFA, &HC3, &H4E, _
            &H8, &H2E, &HA1, &H66, &H28, &HD9, &H24, &HB2, &H76, &H5B, &HA2, &H49, &H6D, &H8B, &HD1, &H25, _
            &H72, &HF8, &HF6, &H64, &H86, &H68, &H98, &H16, &HD4, &HA4, &H5C, &HCC, &H5D, &H65, &HB6, &H92, _
            &H6C, &H70, &H48, &H50, &HFD, &HED, &HB9, &HDA, &H5E, &H15, &H46, &H57, &HA7, &H8D, &H9D, &H84, _
            &H90, &HD8, &HAB, &H0, &H8C, &HBC, &HD3, &HA, &HF7, &HE4, &H58, &H5, &HB8, &HB3, &H45, &H6, _
            &HD0, &H2C, &H1E, &H8F, &HCA, &H3F, &HF, &H2, &HC1, &HAF, &HBD, &H3, &H1, &H13, &H8A, &H6B, _
            &H3A, &H91, &H11, &H41, &H4F, &H67, &HDC, &HEA, &H97, &HF2, &HCF, &HCE, &HF0, &HB4, &HE6, &H73, _
            &H96, &HAC, &H74, &H22, &HE7, &HAD, &H35, &H85, &HE2, &HF9, &H37, &HE8, &H1C, &H75, &HDF, &H6E, _
            &H47, &HF1, &H1A, &H71, &H1D, &H29, &HC5, &H89, &H6F, &HB7, &H62, &HE, &HAA, &H18, &HBE, &H1B, _
            &HFC, &H56, &H3E, &H4B, &HC6, &HD2, &H79, &H20, &H9A, &HDB, &HC0, &HFE, &H78, &HCD, &H5A, &HF4, _
            &H1F, &HDD, &HA8, &H33, &H88, &H7, &HC7, &H31, &HB1, &H12, &H10, &H59, &H27, &H80, &HEC, &H5F, _
            &H60, &H51, &H7F, &HA9, &H19, &HB5, &H4A, &HD, &H2D, &HE5, &H7A, &H9F, &H93, &HC9, &H9C, &HEF, _
            &HA0, &HE0, &H3B, &H4D, &HAE, &H2A, &HF5, &HB0, &HC8, &HEB, &HBB, &H3C, &H83, &H53, &H99, &H61, _
            &H17, &H2B, &H4, &H7E, &HBA, &H77, &HD6, &H26, &HE1, &H69, &H14, &H63, &H55, &H21, &HC, &H7D}

        rcon = { _
            &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, _
            &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, _
            &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, _
            &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, _
            &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, _
            &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, _
            &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, _
            &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, _
            &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, _
            &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, _
            &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, _
            &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, _
            &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, _
            &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, _
            &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, _
            &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB}

        isEncode = False
        If bEncrpyt Then
            isEncode = True
        End If

        For i = 0 To 15
            nonce(i) = 0
        Next

        For i = 0 To (Len(encryptKey) - 1)
            aesKey(i) = Asc(Mid(encryptKey, i + 1, 1))
        Next

        For i = Len(encryptKey) To 31
            aesKey(i) = 0
        Next

        expandedKey = expandKey(aesKey, sbox, rcon)

        Dim oFile1 As MyStringStream
        Dim oFile2 As MyStringStream
        oFile1 = New MyStringStream
        oFile2 = New MyStringStream

        oFile1.CreateStream(sFile)

     
            Do Until oFile1.AtEndofStream
                sPlain = oFile1.ReadString(1024)
                sCipher = ""
                j = 0
                isDone = False

                Do Until isDone
                    sTemp = Mid(sPlain, j * 16 + 1, 16)

                    If Len(sTemp) < 16 Then
                        For i = Len(sTemp) To 15
                            sTemp = sTemp & Chr(0)
                        Next
                    End If

                    For i = 0 To 15
                        block(i) = Asc(Mid(sTemp, (i Mod 4) * 4 + (i \ 4) + 1, 1))
                    Next

                    If (j + 1) * 16 >= Len(sPlain) Then
                        isDone = True
                    End If

                    j = j + 1

                    If isEncode Then
                        r = 0
                        For i = 0 To 15
                            block(i) = block(i) Xor nonce(i) Xor expandedKey((i Mod 4) * 4 + (i \ 4))
                        Next

                        For x = 1 To 13
                            block(0) = sbox(block(0))
                            block(1) = sbox(block(1))
                            block(2) = sbox(block(2))
                            block(3) = sbox(block(3))

                            intTemp = sbox(block(4))
                            block(4) = sbox(block(5))
                            block(5) = sbox(block(6))
                            block(6) = sbox(block(7))
                            block(7) = intTemp

                            intTemp = sbox(block(8))
                            block(8) = sbox(block(10))
                            block(10) = intTemp
                            intTemp = sbox(block(9))
                            block(9) = sbox(block(11))
                            block(11) = intTemp

                            intTemp = sbox(block(12))
                            block(12) = sbox(block(15))
                            block(15) = sbox(block(14))
                            block(14) = sbox(block(13))
                            block(13) = intTemp

                            r = x * 16
                            For i = 0 To 3
                                temp(0) = block(i)
                                temp(1) = block(i + 4)
                                temp(2) = block(i + 8)
                                temp(3) = block(i + 12)

                                block(i) = g2(temp(0)) Xor temp(3) Xor temp(2) Xor g3(temp(1)) Xor expandedKey(r + i * 4)
                                block(i + 4) = g2(temp(1)) Xor temp(0) Xor temp(3) Xor g3(temp(2)) Xor expandedKey(r + i * 4 + 1)
                                block(i + 8) = g2(temp(2)) Xor temp(1) Xor temp(0) Xor g3(temp(3)) Xor expandedKey(r + i * 4 + 2)
                                block(i + 12) = g2(temp(3)) Xor temp(2) Xor temp(1) Xor g3(temp(0)) Xor expandedKey(r + i * 4 + 3)
                            Next
                        Next

                        block(0) = sbox(block(0)) Xor expandedKey(224)
                        block(1) = sbox(block(1)) Xor expandedKey(228)
                        block(2) = sbox(block(2)) Xor expandedKey(232)
                        block(3) = sbox(block(3)) Xor expandedKey(236)

                        intTemp = sbox(block(4)) Xor expandedKey(237)
                        block(4) = sbox(block(5)) Xor expandedKey(225)
                        block(5) = sbox(block(6)) Xor expandedKey(229)
                        block(6) = sbox(block(7)) Xor expandedKey(233)
                        block(7) = intTemp

                        intTemp = sbox(block(8)) Xor expandedKey(234)
                        block(8) = sbox(block(10)) Xor expandedKey(226)
                        block(10) = intTemp
                        intTemp = sbox(block(9)) Xor expandedKey(238)
                        block(9) = sbox(block(11)) Xor expandedKey(230)
                        block(11) = intTemp

                        intTemp = sbox(block(12)) Xor expandedKey(231)
                        block(12) = sbox(block(15)) Xor expandedKey(227)
                        block(15) = sbox(block(14)) Xor expandedKey(239)
                        block(14) = sbox(block(13)) Xor expandedKey(235)
                        block(13) = intTemp

                        For i = 0 To 15
                            nonce(i) = block(i)
                        Next
                    Else
                        For i = 0 To 15
                            priorCipher(i) = block(i)
                        Next

                        block(0) = sboxinv(block(0) Xor expandedKey(224))
                        block(1) = sboxinv(block(1) Xor expandedKey(228))
                        block(2) = sboxinv(block(2) Xor expandedKey(232))
                        block(3) = sboxinv(block(3) Xor expandedKey(236))

                        intTemp = sboxinv(block(4) Xor expandedKey(225))
                        block(4) = sboxinv(block(7) Xor expandedKey(237))
                        block(7) = sboxinv(block(6) Xor expandedKey(233))
                        block(6) = sboxinv(block(5) Xor expandedKey(229))
                        block(5) = intTemp

                        intTemp = sboxinv(block(8) Xor expandedKey(226))
                        block(8) = sboxinv(block(10) Xor expandedKey(234))
                        block(10) = intTemp
                        intTemp = sboxinv(block(9) Xor expandedKey(230))
                        block(9) = sboxinv(block(11) Xor expandedKey(238))
                        block(11) = intTemp

                        intTemp = sboxinv(block(12) Xor expandedKey(227))
                        block(12) = sboxinv(block(13) Xor expandedKey(231))
                        block(13) = sboxinv(block(14) Xor expandedKey(235))
                        block(14) = sboxinv(block(15) Xor expandedKey(239))
                        block(15) = intTemp

                        For x = 13 To 1 Step -1
                            r = x * 16

                            For i = 0 To 3
                                temp(0) = block(i) Xor expandedKey(r + i * 4)
                                temp(1) = block(i + 4) Xor expandedKey(r + i * 4 + 1)
                                temp(2) = block(i + 8) Xor expandedKey(r + i * 4 + 2)
                                temp(3) = block(i + 12) Xor expandedKey(r + i * 4 + 3)

                                block(i) = g14(temp(0)) Xor g9(temp(3)) Xor g13(temp(2)) Xor g11(temp(1))
                                block(i + 4) = g14(temp(1)) Xor g9(temp(0)) Xor g13(temp(3)) Xor g11(temp(2))
                                block(i + 8) = g14(temp(2)) Xor g9(temp(1)) Xor g13(temp(0)) Xor g11(temp(3))
                                block(i + 12) = g14(temp(3)) Xor g9(temp(2)) Xor g13(temp(1)) Xor g11(temp(0))
                            Next

                            block(0) = sboxinv(block(0))
                            block(1) = sboxinv(block(1))
                            block(2) = sboxinv(block(2))
                            block(3) = sboxinv(block(3))

                            intTemp = sboxinv(block(4))
                            block(4) = sboxinv(block(7))
                            block(7) = sboxinv(block(6))
                            block(6) = sboxinv(block(5))
                            block(5) = intTemp

                            intTemp = sboxinv(block(8))
                            block(8) = sboxinv(block(10))
                            block(10) = intTemp
                            intTemp = sboxinv(block(9))
                            block(9) = sboxinv(block(11))
                            block(11) = intTemp

                            intTemp = sboxinv(block(12))
                            block(12) = sboxinv(block(13))
                            block(13) = sboxinv(block(14))
                            block(14) = sboxinv(block(15))
                            block(15) = intTemp
                        Next

                        r = 0
                        For i = 0 To 15
                            block(i) = block(i) Xor expandedKey((i Mod 4) * 4 + (i \ 4)) Xor nonce(i)
                            nonce(i) = priorCipher(i)
                        Next
                    End If

                    For i = 0 To 15
                        sCipher = sCipher & Chr(block((i Mod 4) * 4 + (i \ 4)))
                    Next
                Loop

                oFile2.WriteString(sCipher)
            Loop
        RunAES = oFile2.ReadAll
    End Function

    Public Function keyScheduleCore(ByVal row, ByVal a, ByRef box, ByRef rcon)



        Dim result(4), i

        For i = 0 To 3
            result(i) = box(row((i + 5) Mod 4))
        Next

        result(0) = result(0) Xor rcon(a)
        keyScheduleCore = result
    End Function

    Public Function expandKey(ByRef key, ByRef box, ByRef rcon)

        Dim rConIter, temp, i, result(240)

        ReDim temp(4)
        rConIter = 1

        For i = 0 To 31
            result(i) = key(i)
        Next

        For i = 32 To 239 Step 4
            temp(0) = result(i - 4)
            temp(1) = result(i - 3)
            temp(2) = result(i - 2)
            temp(3) = result(i - 1)

            If i Mod 32 = 0 Then
                temp = keyScheduleCore(temp, rConIter, box, rcon)
                rConIter = rConIter + 1
            End If

            If i Mod 32 = 16 Then
                temp(0) = box(temp(0))
                temp(1) = box(temp(1))
                temp(2) = box(temp(2))
                temp(3) = box(temp(3))
            End If

            result(i) = result(i - 32) Xor temp(0)
            result(i + 1) = result(i - 31) Xor temp(1)
            result(i + 2) = result(i - 30) Xor temp(2)
            result(i + 3) = result(i - 29) Xor temp(3)
        Next

        expandKey = result
    End Function

End Class
