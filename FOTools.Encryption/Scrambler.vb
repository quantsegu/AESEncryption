Public Class Scrambler
    Public Function scrambleString(str As String) As String
        Dim b As Byte
        Dim out As String
        Dim i As Int64
        out = vbNullString
        For i = 1 To Len(str)
            b = Asc(Mid(str, i, 1))
            b = 255 - b
            b = rotateR(b, i)
            out = out & myhex(b)
        Next
        scrambleString = out
    End Function
    Public Function descrableString(str As String) As String
        Dim stream As MyStringStream
        stream = New MyStringStream
        Dim hx As String
        Dim dec As Byte
        Dim outStr As String
        Dim b As Byte
        outStr = vbNullString
        stream.CreateStream(str)
        Dim i As Int64
        i = 1
        Do While Not stream.AtEndofStream
            hx = "&H" & stream.ReadString(2)
            dec = CByte(hx)
            b = rotateR(dec, i)
            b = 255 - b
            outStr = outStr & Chr(b)
            i = i + 1
        Loop
        descrableString = outStr
    End Function
    Private Function myhex(b As Byte) As String
        Dim s As String
        s = Hex(b)
        If Len(s) < 2 Then
            s = "0" & s
        End If
        myhex = s
    End Function
    Private Function rotateL(b As Byte, ByVal bits As Integer) As Byte
        If bits > 8 Then
            bits = bits Mod 8
        End If
        Dim i As Int32
        For i = 1 To bits
            b = rotateLeft(b)
        Next
        rotateL = b
    End Function

    Private Function rotateR(b As Byte, ByVal bits As Integer) As Byte
        If bits > 8 Then
            bits = bits Mod 8
        End If
        Dim i As Int32
        For i = 1 To bits
            b = rotateRight(b)
        Next
        rotateR = b
    End Function

    Private Function rotateRight(NewRot As Byte) As Byte
        Dim blnBit As Boolean
        blnBit = ((NewRot And &H1) = &H1)
        NewRot = NewRot \ 2
        If blnBit Then NewRot = NewRot Or &H80
        rotateRight = NewRot
    End Function
    Private Function rotateLeft(ByVal NewRot As Byte) As Byte
        Dim blnBit As Boolean
        blnBit = ((NewRot And &H80) = &H80)
        NewRot = NewRot And Not &H80
        NewRot = NewRot * 2
        If blnBit Then NewRot = NewRot Or &H1
        rotateLeft = NewRot
    End Function
End Class
