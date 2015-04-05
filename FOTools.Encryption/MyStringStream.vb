Public Class MyStringStream
    Private buffer As String
    Private currentPos As Long
    Private totalLength As Long
    Public Property AtEndofStream() As Boolean
        Get
            If currentPos < totalLength Then
                AtEndofStream = False
            Else
                AtEndofStream = True
            End If
        End Get
        Set(value As Boolean)
            buffer = value
            currentPos = 1
            totalLength = Len(buffer)
        End Set
    End Property
    Public Function ReadString(count As Long) As String

        Dim retBytes As String

        If currentPos + count - 1 <= totalLength Then
            retBytes = Mid(buffer, currentPos, count)
            currentPos = currentPos + count
        Else
            retBytes = Right(buffer, totalLength - currentPos + 1)
            currentPos = totalLength
        End If
        ReadString = retBytes
    End Function
    Public Function ReadAll() As String
        ReadAll = buffer
        currentPos = totalLength
    End Function
    Public Sub Reset()
        buffer = ""
        currentPos = 1
        totalLength = 0
    End Sub
    Public Sub Rewind()
        currentPos = 1
    End Sub
    Public Sub CreateStream(ByVal str As String)
        buffer = str
        currentPos = 1
        totalLength = Len(buffer)
    End Sub
    Public Sub WriteString(ByVal s As String)
        buffer = buffer & s
        totalLength = totalLength + Len(s)
    End Sub
End Class
