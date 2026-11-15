"""Uji autentikasi, CRUD, foreign key, dan persistensi tanpa membuka GUI."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from main import Database

class DatabaseTest(unittest.TestCase):
    def test_workflow(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'test.db'
            db = Database(path)
            self.assertEqual(len(db.rows("SELECT name FROM sqlite_master WHERE type='table'")), 3)
            db.create_user('abim', 'belajar123')
            self.assertTrue(db.authenticate('abim', 'belajar123'))
            self.assertFalse(db.authenticate('abim', 'salah'))
            self.assertFalse(db.authenticate("' OR 1=1 --", 'belajar123'))
            with self.assertRaises(ValueError):
                db.create_user('x', '123')
            with self.assertRaises(sqlite3.IntegrityError):
                db.create_user('abim', 'password123')
            category = db.write('INSERT INTO kategori(nama) VALUES(?)', ('Makanan',))
            product = db.write('INSERT INTO produk(nama,kategori_id,harga,stok) VALUES(?,?,?,?)', ('Pizza', category, 10000, 20))
            with self.assertRaises(sqlite3.IntegrityError):
                db.write('DELETE FROM kategori WHERE id=?', (category,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.write('UPDATE produk SET stok=-1 WHERE id=?', (product,))
            db.write('UPDATE produk SET stok=? WHERE id=?', (25, product))
            db.write('UPDATE kategori SET nama=? WHERE id=?', ('Pizza Teflon', category))
            self.assertEqual(db.rows('SELECT stok FROM produk WHERE id=?', (product,))[0][0], 25)
            self.assertEqual(db.rows('SELECT nama FROM kategori')[0][0], 'Pizza Teflon')
            db.conn.close()
            db = Database(path)
            self.assertTrue(db.authenticate('abim', 'belajar123'))
            self.assertEqual(db.rows('SELECT nama FROM produk')[0][0], 'Pizza')
            db.write('DELETE FROM produk WHERE id=?', (product,))
            db.write('DELETE FROM kategori WHERE id=?', (category,))
            self.assertEqual(db.rows('SELECT * FROM produk'), [])
            self.assertEqual(db.rows('SELECT * FROM kategori'), [])
            db.conn.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
